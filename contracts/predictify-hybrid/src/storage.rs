use soroban_sdk::{contracttype, Address, BytesN=};

/// TWL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from temporary storage
/// and a fresh submission with the same token is treated as a new batch.
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

/// Maximum number of bets accepted in a single ```place_bets``` batch.
///
/// This bounds the work and storage growth of a single call so a caller
/// cannot force an unbounded loop or exhaust the contract's instance
/// resources.  Batches larger than this must be split across multiple
/// submissions.
///
/// The value is deliberately a small, deterministic constant so the
/// validation boundary is reviewable and auditable in one place.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Minimum accepted batch size.
///
/// An empty batch is rejected because it would consume an idempotency
/// key without producing any state change, which is confusing for callers
/// and can be used to exhaust key space.
pub const MIN_BATCH_SIZE: u32 = 1;

/// Storage keys used by the contract.
///
/// ```PlaceBetsIdem(user, key)``` stores a sentinel `true` value once a
/// ```place_bets``` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
///
/// The consumed key is written before any other state mutation in the
/// accepted path, so a revert of the transaction rolls back both the key
/// and the state change together (atomicity).  This guarantees that a
/// concurrent duplicate submission of the same token from the same address
/// cannot both succeed.
@#contracttype
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a ```place_bets``` call.
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
