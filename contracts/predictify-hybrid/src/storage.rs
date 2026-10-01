use soroban_sdk::{contracttype, Address, BytesN, Env};

use crate::errors::Error;

/// TWL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the network deletes the receipt and a fresh submission
/// with the same token is treated as a new batch.
///
/// **Network floor.** A temporary entry can never live for less than the
/// network's `min_temp_entry_ttl` setting. A receipt is therefore written
/// with `extend_ttl(IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS)` — see
/// [`RECEIPT_EXTEND_THRESHOLD_LEDGERS`] — which renews it to exactly this
/// window on every network where `min_temp_entry_ttl` does not already
/// exceed it. If `min_temp_entry_ttl` were ever configured above
/// [`IDEM_KEY_TTL_LEDGERS`], the extension is skipped and the entry
/// simply outlives the target window, which is safe. A caller must not
/// assume a token becomes reusable sooner than this, nor later.
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

/// Maximum number of bets in a single `place_bets` batch.
///
/// This bound is enforced before any state mutation so that an
/// oversized batch is rejected atomically without consuming the
/// caller's idempotency key. The value is deliberately small enough
/// to keep the batch and its emitted events well within the network'
/// transaction resource limits, and large enough for realistic use.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` stores a sentinel `true` value once a
/// `place_bets` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency receipt for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
    /// Ledger sequence at which the matching `PlaceBetsIdem` sentinel was
    /// consumed, used to enforce [`IDEM_KEY_TTL_LEDGERS`] in contract code.
    PlaceBetsIdemLedger(Address, BytesN<32>),
}

/// Validate the existing marker before reserving a token.
///
/// The persisted compatibility contract is an instance-storage boolean `true`
/// under `["PlaceBetsIdem", caller, token]`. Do not change the enum variant name,
/// field order or value encoding without a tested migration. Read as `Val`
/// first so incompatible values produce a stable contract error rather than
/// a conversion panic. Only absence permits a reservation; invalid values are
/// never treated as unused or silently overwritten.
///
/// The authenticated entry point must validate its batch before calling this
/// helper and write the marker in the same transaction as the batch effects.
pub(crate) fn is_idempotency_key_consumed(env: &Env, key: &DataKey) -> Result<bool, Error> {
    match env.storage().instance().get::<_, Val>(key) {
        None => Ok(false),
        Some(value) => match bool::try_from_val(env, &value) {
            Ok(true) => Ok(true),
            // `false` was never written by a valid caller. Fail closed for it
            // and for all unknown layouts; do not disclose the saved value.
            _ => Err(Error::InvalidIdempotencyState),
        },
    }
}

/// Returns `true` if the idempotency key has already been consumed by
/// a successful batch from the same caller.
pub fn is_idempotency_key_consumed(env: &Env, caller: &Address, key: &BytesN<32>) -> bool {
    env.storage()
        .instance()
        .has(&DataKey::PlaceBetsIdem(caller.clone(), key.clone()))
}

/// Marks the idempotency key as consumed and extends its TT\.
///
/// This function is the only place that writes the sentinel, so the
/// invariant "consumed implies batch applied" holds by construction.
/// It must be called after all validation and state mutations succeed.
pub fn consume_idempotency_key(env: &Env, caller: &Address, key: &BytesN<32>) {
    let storage = env.storage().instance();
    storage.set(
        &DataKey::PlaceBetsIdem(caller.clone(), key.clone()),
        &true,
    );
    storage.extend_ttl(
        &DataKey::PlaceBetsIdem(caller.clone(), key.clone()),
        IDEM_KEY_TTL_LEDGERS,
        IDEM_KEY_TTL_LEDGERS,
    );
}
