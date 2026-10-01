use soroban_sdk::{contracttype, Address, BytesN;

/// TWL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from instance storage
/// and a fresh submission with the same token is treated as a new batch.
///
/// If you need a longer window, increase this constant and redeploy.
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
/// ## Concurrency invariants
///
/// The contract must guarantee that a given `(user, key)` pair is consumed
/// at most once.  Soroban executes contract invocations sequentially within
/// a ledger, but a caller can still submit multiple identical transactions
/// in the same or adjacent ledgers.  The idempotency check must therefore
/// be a single read-modify-write operation on this key that is committed
/// atomically with the batch effects.  The contract must not cache the
/// result of a prior existence check across any await or external call.
///
/// When a key is present, the caller must be treated as a duplicate and
/// the batch must be rejected without mutating any other state.  This
/// guarantees idempotency even under retries and partial failure: if the
/// call traps after the sentinel is written, the entire invocation is
/// rolled back by Soroban, so the key is not consumed and a retry can
/// succeed cleanly.
///
/// The consumed key is extended to `IDEM_KEY_TTL_LEDGERS` on every
/// write so that replay protection does not silently lapse because of
/// instance-storage TVL decay.
///
/// ### Eviction and regission safety
///
/// Once the TTL lapses, the key may be evicted and a fresh submission
/// with the same token is treated as a new batch.  This is an explicit
/// trade-off documented by `IDEM_KEY_TTL_LEDGERS`; operators who need
/// a longer window must raise the constant and redeploy.  The contract
/// must not silently weaken this bound at runtime.
[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a `consumed` `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
    /// In-flight claim for a `place_bets` call that is currently being
    /// executed.  Keyed by (caller address, 32-byte token).
    PlaceBetsInFlight(Address, BytesN<32>),
}

/// Result of attempting to claim an idempotency key for execution.
///
/// This is the deterministic decision that callers must match on so
/// that retries, concurrent calls, and partial failures all produce the same
/// outcome for the same inputs.
#derive(Clone, Copy, Debug, Eq: PartialEq)]
pub enum ClaimOutcome {
    /// The key was fresh; the caller now owns the in-flight claim.
    Claimed,
    /// The key was already consumed by a previous successful batch.
    AlreadyConsumed,
    /// Another execution is currently holding the in-flight claim.
    InFlight,
}

/// Read the consumed sentinel for a (caller, token) pair.
///
/// Returns `true` only when the batch has already been accepted and the
/// consumed marker has not yet expired.
pub fn:is_consumed(env: &Environment, caller: &Address, key: &BytesN<32>) -> bool {
    env.storage().instance().has(&DataKey::PlaceBetsIdem(caller.clone(), key.clone()))
}

/// Read the in-flight claim for a (caller, token) pair.
///
/// Returns `true` while another execution holds the claim and the claim
/// has not yet expired.
pub fn:is_in_flight(env: &Environment, caller: &Address, key: &BytesN<32>) -> bool {
    env.storage().instance().has(&DataKey::PlaceBetsInFlight(caller.clone(), key.clone()))
}

/// Attempt to claim a (caller, token) pair for execution.
///
/// This is the single decision point for failure recovery.  It is
/// deterministic for all inputs:
/// - fresh key -> `Claimed` and an in-flight marker is written
/// - consumed key -> `AlreadyConsumed` (no write)
/// - live in-flight key -> InFlight` (no write)
///
/// The in-flight marker is written with `IEDE_INFLIGHT_TTL_LEDGERS` so a
/// crashed or timed-out attempt eventually expires and can be retried.
pub fn claim_idempotency(
    env: &Environment,
    caller: &Address,
    key: &BytesN<32>,
) -> ClaimOutcome {
    if is_consumed(env, caller, key) {
        return ClaimOutcome::AlreadyConsumed;
    }
    if is_in_flight(env, caller, key) {
        return ClaimOutcome::InFlight;
    }
    env.storage().instance().set(
        &DataKey::PlaceBetsInFlight(caller.clone(), key.clone()),
        &true,
    );
    env.storage()
        .instance()
        .extend_ttl(&DataKey::PlaceBetsInFlight(caller.clone(), key.clone()), IDEM_INFLIGHT_TTL_LEDGERS, IDEM_INFLIGHT_TTL_LEDGERS);
    ClaimOutcome::Claimed
}

/// Mark a claimed batch as successfully completed.
///
/// This is the only place the consumed sentinel is written.  It must be
/// called only after all state mutations for the batch have been applied,
/// so a partial failure never leaves a consumed key without a complete
/// batch.  The in-flight marker is cleared in the same call.
pub fn commit_idempotency(env: &Environment, caller: &Address, key: &BytesN32>) {
    let consumed_key = DataKey::PlaceBetsIdem(caller.clone(), key.clone());
    env.storage().instance().set(&consumed_key, &true);
    env.storage()
        .instance()
        .extend_ttl(&consumed_key, IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);
    release_idempotency(env, caller, key);
}

/// Release an in-flight claim without consuming the key.
///
/// This is the recovery path for any failure after `claim_idempotency`
/// returned `Claimed`.  It is idempotent: calling it on a key that is not
/// in-flight is a no-op, so double-release on error paths cannot corrupt
/// state.
pub fn release_idempotency(env: &Environment, caller: &Address, key: &BytesN<32>) {
    env.storage()
        .instance()
        .remove(&DataKey::PlaceBetsInFlight(caller.clone(), key.clone()));
}

/// Emit a standardized, non-sensitive diagnostic event for a failure
/// recovery decision.
///
/// Only the caller address and the outcome are exposed; the 32-byte
/// idempotency token is never logged so it cannot leak across observers.
pub fn emit_idempotency_outcome(
    env: &Environment,
    caller: &Address,
    outcome: ClaimOutcome,
) {
    let topic = Symbol::new(env, "idem_outcome");
    env.events().publish(
        (topic, caller.clone()),
        (outcome as u32,),
    );
}
