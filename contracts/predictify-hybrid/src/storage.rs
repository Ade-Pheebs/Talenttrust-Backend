use soroban_sdk::{contracttype, Address, BytesN=};

/// TWL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the network deletes the receipt and a fresh submission
/// with the same token is treated as a new batch.
///
/// **Network floor.** A temporary entry can never live for less than the
/// network's `min_temp_entry_ttl` setting, so the *effective* replay
/// window is `max(IDEM_KEY_TTL_LEDGERS, min_temp_entry_ttl)`. The
/// published minimum is 16 ledgers, far below this value, so on any
/// known network the value below is the effective window. A caller must
/// not assume a token becomes reusable sooner than this, nor later.
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

/// Lower bound on the *remaining* TTL a consumed idempotency receipt must
/// have before [`IDEM_KEY_TTL_LEDGERS`] is (re)applied to it.
///
/// `extend_ttl(threshold, extend_to)` is a no-op when the entry's live
/// TTL is already at or above `threshold`. Passing the target TTL as the
/// threshold — the previous behavior — therefore skipped the extension
/// on almost every call, so the replay window was really whatever the
/// host default happened to be. This value sits comfortably below the
/// target so the window is genuinely renewed each time a receipt is
/// written.
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
/// `PlaceBetsIdem(caller, key)` stores a [`crate::bets::BatchReceipt`]
/// once a `place_bets` batch has been accepted. The composite key binds
/// the token to the submitting address so two different callers may
/// reuse the same 32-byte token independently without conflict, and no
/// caller can consume or replay another caller's token.
///
/// # Why temporary storage, and not instance or persistent
///
/// **Not instance storage.** The contract instance is a *single* ledger
/// entry. Every key written under it grows that one entry, and the host
/// rejects the write once the serialized entry exceeds `max_entry_size`
/// (64 KiB by default). That rejection is not per-key: it fails *every*
/// subsequent mutation of the instance, so a caller who merely kept
/// submitting batches with fresh tokens would eventually push the entry
/// over the limit and permanently disable `place_bets` for everybody.
/// There is no on-chain remedy short of a contract upgrade, and stake
/// already accepted by users would be stranded. This is the defect the
/// idempotency feature shipped with.
///
/// **Not persistent storage.** Deduplication requires *reading* the
/// receipt, and an expired persistent entry cannot be read at all: the
/// host rejects the whole transaction, because the entry has been
/// archived and restoring it costs a fee. A persistent receipt would
/// therefore turn the documented "after expiry the token may be reused"
/// behavior into "after expiry the token is permanently unusable, with an
/// opaque ledger-level failure" — worse than either reusing the token or
/// losing the response would have been. (The test host surfaces the same
/// condition as `accessed a key that has been archived`.)
///
/// **Temporary storage** gives exactly the required semantics: one
/// ledger entry per key, so the instance entry stays a constant size
/// however many batches succeed; an entry that has aged out simply reads
/// as absent; and the network deletes it at `liveUntil`, so receipts
/// cannot accumulate either.
///
/// See the module documentation in [`crate::bets`] for the invariants
/// that depend on this choice.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency receipt for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN),
}

/// Returns `true` if the given idempotency key has already been
/// consumed by this caller.
///
/// This is a pure read: it does not mutate state and does not extend the
/// TTL.  Callers must not rely on this as a reservation — the authoritative
/// check is the compare-and-set in [`crate_idempotent_sentinel`].
pub fn is_idempotent_key_consumed(env: &Env, caller: &Address, key: &BytesN) -> bool {
    env.storage()
        .instance()
        .has(&DataKey::PlaceBetsIdem(caller.clone(), key.clone()))
}

/// Atomically consumes an idempotency key for a caller.
///
/// Returns `true` if the key was free and has now been consumed by this
/// call, false if it was already consumed.  The check and the write are
/// performed in a single `instance()` operation so concurrent invocations
/// cannot both observe the key as free.  The TTL is extended at the same
/// time to ensure the sentinel outlives the replay window.
///
/// ### Failure mode
///
/// If this function returns `true` but the calling transaction later
/// fails, Soroban rolls back the entire invocation, including this write,
/// so the key remains free for a clean retry.  This is the key property
/// that makes retries idempotent.
pub fn consume_idempotency_key(
    env: &Env,
    caller: &Address,
    key: &BytesN,
) -> bool {
    let storage = env.storage().instance();
    let data_key = DataKey::PlaceBetsIdem(caller.clone(), key.clone());

    if storage.has(&data_key) {
        // Already consumed.  Refresh the TTL on the existing sentinel so a
        // replay attempt does not silently extend the window beyond the
        // original application.
        storage.extend_ttl(&data_key, IDEM_KEY_TTL_LEDGERS, 0);
        return false;
    }

    // Compare-and-set: the has() check above and this write are executed
    // within the same atomic invocation, so no other invocation can
    // interleave between them.
    storage.set(&data_key, &true);
    storage.extend_ttl(&data_key, IDEM_KEY_TTL_LEDGERS, 0);
    true
}
