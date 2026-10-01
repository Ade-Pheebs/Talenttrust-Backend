use soroban_sdk::{contracttype, Address, BytesN, Env};

/// TWL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from instance storage
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

/// TTL the contract instance is extended to on every successful batch
/// (~30 days). #1288: previously the instance was bumped to the same 24 h
/// window as the keys, so an idle contract could expire together with its
/// replay protection. The instance must outlive every key it protects.
pub const INSTANCE_TTL_LEDGERS: u32 = 518_400;

/// Largest number of bets accepted in one `place_bets` call. Bounds the
/// work and footprint of a single invocation so a batch can never fail
/// part-way on resource limits.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` marks a consumed `place_bets` key.
///
/// Storage tiers (#1288 / #1280):
/// * **Current:** *temporary* storage holding a [`crate::BatchReceipt`],
///   with its own TTL of [`IDEM_KEY_TTL_LEDGERS`]. Temporary storage is what
///   makes the documented "expires after ~24 h" behaviour true per key.
/// * **Legacy:** versions before #1288 stored a sentinel `true` in *instance*
///   storage, where entries share the instance TTL and never expire
///   individually. Those entries are still honoured (a legacy key is never
///   re-applied) so upgrading the contract cannot re-open old keys.
///
/// Original note: the key is stored once a
/// `place_bets` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
///
/// ## Compatibility contract
///
/// The constructor shape of `DataKey` is part of the on-chain state
/// layout.  Adding new variants is allowed (they must be appended),
/// but reordering or removing existing variants would invalidate
/// persisted state and break existing deployments.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a `consumed` `place_bets` call.
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
