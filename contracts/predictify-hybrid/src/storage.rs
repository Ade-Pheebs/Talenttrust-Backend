use soroban_sdk::{contracttype, Address, BytesN, Env};

use crate::errors::Error;

/// TWL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// Each temporary entry has an independent lifetime. The stored deadline
/// also enforces expiry if network minimum retention or a rent extension
/// keeps the physical entry alive longer. A key is consumed through its
/// deadline ledger (inclusive), and may be reused in the following ledger.
///
/// If you need a longer window, increase this constant and redeploy.
///
/// ## Compatibility contract
///
/// This constant is part of the public API and is re-exported from
/// `lib.rs`.  Changing it changes the replay-protection window for
/// any future deployment.  It must not be lowered without a migration
/// plan, because that would allow a replay of an already-applied batch.
pub const IDEM_KEY_TTL_LEDGERS: u32 = 17_280; // ~24 h at 5 s/ledger

/// Threshold passed to `extend_ttl` when a receipt is written.
///
/// A receipt is written exactly once and is never re-extended: a replay
/// is rejected outright rather than renewing the window. So the threshold
/// is only ever compared against a *freshly created* entry, whose
/// remaining TTL is the network's `min_temp_entry_ttl`, not an arbitrary
/// caller-supplied value.
///
/// That makes the target TTL the correct threshold, and a lower one a
/// latent bug: with a threshold below `min_temp_entry_ttl` the extension
/// is skipped and the receipt silently dies after `min_temp_entry_ttl`
/// instead of the documented [`IDEM_KEY_TTL_LEDGERS`]. Setting the
/// threshold to the target makes the window independent of network
/// configuration: it fires whenever the entry does not already outlive the
/// window, and the no-op case is the one where it does not matter.
pub const RECEIPT_EXTEND_THRESHOLD_LEDGERS: u32 = IDEM_KEY_TTL_LEDGERS;

/// Retained so existing imports keep compiling.
///
/// This threshold used to guard the receipt extension, which made the
/// replay window depend on the network's `min_temp_entry_ttl` — see
/// [`RECEIPT_EXTEND_THRESHOLD_LEDGERS`] for why that was wrong. It is no
/// longer used for the receipt; do not reintroduce it there.
pub const IDEM_KEY_TTL_THRESHOLD_LEDGERS: u32 = 1_000; // ~1.4 h at 5 s/ledger

/// TTL applied to the contract instance and its Wasm code every time a
/// batch is accepted.
///
/// The contract instance is a persistent-durability ledger entry with its
/// own TTL, and it is *not* kept alive by the per-receipt TTLs above.
/// Without bumping it here, a contract that fell idle long enough would
/// be archived by the network, and every subsequent `place_bets` would
/// fail with a host error — including calls whose receipts are still
/// live. Recovery would need a paid restore transaction, so the contract
/// would be unavailable exactly when users are trying to submit bets.
///
/// Set comfortably **above** [`IDEM_KEY_TTL_LEDGERS`] so a live receipt
/// never outlives the contract that minted it in ordinary operation.
pub const CONTRACT_TTL_LEDGERS: u32 = 34_560; // ~48 h at 5 s/ledger

/// Lower bound on the *remaining* TTL of the contract instance and code
/// before [`CONTRACT_TTL_LEDGERS`] is (re)applied to them.
///
/// Must be far *below* [`CONTRACT_TTL_LEDGERS`]: the bump only fires when
/// an entry is already close to expiring, so a threshold at or above the
/// network's initial instance TTL would never fire and would also risk
/// *shortening* a longer-lived instance.
pub const CONTRACT_TTL_THRESHOLD_LEDGERS: u32 = 1_000; // ~1.4 h at 5 s/ledger

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` stores an inclusive ledger deadline in
/// temporary storage once a `place_bets` batch has been accepted. The key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency receipt for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
    /// Inclusive cutoff for legacy instance-storage boolean sentinels.
    /// Set once by the first successful nonzero-key submission after upgrade.
    LegacyIdemDeadline,
}

/// Reserve a nonzero token in the same transaction as the batch effects.
///
/// Only the authenticated, validated entry point may call this helper.
/// A host failure or contract error rolls back the reservation and events.
/// Soroban serializes conflicting ledger writes, so two transactions cannot
/// both commit the same live (caller, token) reservation.
///
/// Old boolean sentinels contain no creation ledger. Conservatively reject
/// them until one full window after the first successful new submission.
/// Failed/duplicate calls cannot restart that cutoff. Remove an old sentinel
/// only when its token is successfully reused after the cutoff.
pub(crate) fn consume_idempotency_key(
    env: &Env,
    caller: &Address,
    token: &BytesN<32>,
) -> Result<(), Error> {
    let key = DataKey::PlaceBetsIdem(caller.clone(), token.clone());
    let now = env.ledger().sequence();
    let legacy_deadline: Option<u32> = env.storage().instance().get(&DataKey::LegacyIdemDeadline);

    if env.storage().instance().has(&key) && legacy_deadline.is_none_or(|deadline| now <= deadline)
    {
        return Err(Error::IdempotentBatchAlreadyApplied);
    }
    if let Some(deadline) = env.storage().temporary().get::<_, u32>(&key) {
        if now <= deadline {
            return Err(Error::IdempotentBatchAlreadyApplied);
        }
    }

    // Never silently shorten replay protection or wrap a ledger deadline.
    let deadline = now
        .checked_add(IDEM_KEY_TTL_LEDGERS)
        .ok_or(Error::IdempotencyRetentionUnavailable)?;
    if env.storage().max_ttl() < IDEM_KEY_TTL_LEDGERS {
        return Err(Error::IdempotencyRetentionUnavailable);
    }

    if legacy_deadline.is_none() {
        env.storage()
            .instance()
            .set(&DataKey::LegacyIdemDeadline, &deadline);
    }
    env.storage().instance().remove(&key);
    // Recreate a logically expired entry so its old physical TTL is not reused.
    env.storage().temporary().remove(&key);
    env.storage().temporary().set(&key, &deadline);
    env.storage()
        .temporary()
        .extend_ttl(&key, IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);
    // Keep the contract live for the window; this does not renew token entries.
    env.storage()
        .instance()
        .extend_ttl(IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);
    Ok(())
}
