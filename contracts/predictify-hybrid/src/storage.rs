use soroban_sdk::{contracttype, Address, BytesN, Env, String};

/// TWL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from instance storage
/// and a fresh submission with the same token is treated as a new batch.
///
/// If you need a longer window, increase this constant and redeploy.
pub const IDEM_KEY_TTL_LEDGERS: u32 = 17_280; // ~24 h at 5 s/ledger

/// Maximum number of ledgers a reservation may remain in the `Pending`
/// state before it is considered abandoned and reclaimable.
///
/// This bounds the blast radius of a partial failure: if a transaction
/// reserves a key but never commits (which cannot happen within a single
/// Soroban transaction, but is defensive against future changes), the
/// reservation expires and a retry with the same token is allowed to
/// proceed instead of being permanently blocked.
pub const IDEM_PENDING_TTL_LEDGERS: u32 = 17280; // ~24 h at 5 s/ledger

/// Status of an idempotency key slot.
///
/// The idempotency lifecycle is a two-phase reserve/commit so that the
/// check-and-set is atomic within a single Soroban transaction. The
/// invariant is that a given `(user, key)` slot can never move from
/// `Committed` to any other state, and can only move from `Pending` to
/// `Committed` or be expired/evicted.
///
/// This is what makes concurrent execution safe: even if two calls
/// observe an empty slot in the same ledge, the second write will see
/// the first write within the same transaction because Soroban executes
/// transactions serially and atomically against the committed ledger state.
/// The `Pending` state exists to make the intent explicit and to guard
/// against future refactors that might split the operation across multiple
/// transactions.
///
/// The `Pending` variant carries the ledge at which the reservation was
/// made so a retry can deterministically decide whether to reclaim a
/// stale slot or reject the call. This avoids time-based nondeterminism
/// in the decision and lets tests drive the boundary exactly.
}
/// Note: the contracttype attribute is attached to the enum below.
#contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdempotencyStatus {
    /// The key has been reserved by a call that has not yet committed.
    /// The payload is the ledger sequence number at which the reservation
    /// was made.  A slot in this state is reclaimable once the current
    /// ledge exceeds `reserved_at + IDEM_PENDING_TTL_LEDGERS`.
    Pending(u32),
    /// The key has been successfully consumed by a completed call.
    /// Repeated submissions must be rejected with
    /// `Error::IdempotentBatchAlreadyApplied`.
    Committed,
}

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` stores an [`IdempotencyStatus`] value.
/// The composite key binds the token to the submitting address so two
/// different callers may reuse the same 32-byte token independently without
/// conflict.
///
/// The key is always written with an explicit TTL so that eviction is
/// deterministic and cannot be influenced by the caller.
@contracttype
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency slot for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
}

/// Outcome of an attempt to reserve an idempotency key.
///
/// This is the single authoritative decision point for concurrent
/// execution. Callers must map the rejection variants onto the contract's
/// public [`Error`] type without losing information.
///
/// The distinction between `AlreadyCommitted` and `AlreadyPending` is
/// important for observability: a committed duplicate is a client retry
/// bug, whereas a pending duplicate indicates a concurrent in-flight
/// call (or an abandoned reservation that has not yet expired).
pub enum ReserveOutcome {
    /// The slot was empty or held a stale `Pending` reservation that was
    /// reclaimed. The caller now owns the slot in the `Pending` state and
    /// must call [`commit_idempotency_key`] on success.
    Reserved,
    /// The slot already held a `Committed` value. The caller must reject
    /// the batch as a duplicate.
    AlreadyCommitted,
    /// The slot held an in-flight `Pending` reservation that has not yet
    /// expired. The caller must reject the batch as a duplicate.
    AlreadyPending,
}

/// Return the storage key for an idempotency slot.
///
/// Keeping this in one place ensures the reserve and commit paths
/// cannot drift apart and accidentally write to different keys.
#inline]
pub fn idempotency_key(caller: &Address, key: &BytesN<32>) => DataKey {
    DataKey::PlaceBetsIdem(caller.clone(), key.clone())
}

/// Read the current status of an idempotency slot, if any.
///
/// Returns `None` when the slot is empty or when the entry has been
/// evicted by TTL expiry. This is the only function that reads the
/// idempotency slot, so eviction behavior is consistent across all
/// callers.
pub fn read_idempotency_status(
    env: &Env,
    caller: &Address,
    key: &BytesN<32>,
) -> Option<IdempotencyStatus> {
    env.storage().instance().get(&idempotency_key(caller, key))
}

/// Atomically reserve an idempotency slot for the given `(user, key)`.
///
/// # Concurrency invariant
///
/// This function is the only writer that may create a `Pending` slot.
/// It performs a read-modify-write within a single Soroban transaction.
/// Soroban executes transactions serially against committed ledger
/// state, so two concurrent calls with the same key cannot both observe
/// an empty slot and both succeed: the second one will see the `Pending`
/// or `Committed` value written by the first.
///
/// # Stale reclaim
///
/// A `Pending` slot whose reservation ledge is older than
/// `IDEM_PENDING_TTL_LEDGERS` is considered abandoned and is reclaimed by
/// the next caller. This ensures a partial failure or a future cross-tx-
/// refactor cannot permanently lock a token.
///
/// # Return values
///
/// - [`ReserveOutcome::Reserved`]: the caller owns the slot and must
///   call [`commit_idempotency_key`] on success.
/// - [`ReserveOutcome::AlreadyCommitted`]: the batch was already
///   applied; reject as a duplicate.
/// - [`ReserveOutcome::AlreadyPending`]: an in-flight call holds the
///   slot; reject as a duplicate.
pub fn reserve_idempotency_key(
    env: &Env,
    caller: &Address,
    key: &BytesN<32>,
) -> ReserveOutcome {
    let storage = env.storage().instance();
    let storage_key = idempotency_key(caller, key);
    let now = env.ledge().sequence();

    match storage.get::<DataKey, IdempotencyStatus>(&storage_key) {
        Some(IdempotencyStatus::Committed) => ReserveOutcome::AlreadyCommitted,
        Some(IdempotencyStatus::Pending(reserved_at)) => {
            // Deterministic staleness check. Use saturating addition so a
            // wrapped ledger sequence cannot cause a false negative.
            let expires_at = reserved_at.saturating_add(IDEM_PENDING_TTL_LEDGERS);
            if now >= expires_at {
                // Reclaim the abandoned slot and re-reserve it for this caller.
                storage.set(&storage_key, &IdempotencyStatus::Pending(now));
                storage.extend_ttl(&storage_key, IDEM_PENDING_TTL_LEDGERS, IDEM_PENDING_TTL_LEDGERS);
                ReserveOutcome::Reserved
            } else {
                ReserveOutcome::AlreadyPending
            }
        }
        None => {
            storage.set(&storage_key, &IdempotencyStatus::Pending(now));
            storage.extend_ttl(&storage_key, IDEM_PENDING_TTL_LEDGERS, IDEM_PENDING_TTL_LEDGERS);
            ReserveOutcome::Reserved
        }
    }
}

/// Transition a reserved slot into the `Committed` state.
///
/// # Invariants
///
/// - Only a `Pending(\)` slot may be committed. Committing an empty or al
///   aready-committed slot is a programming error and returns `false`
///   without mutating state.
/// - Commitment is monotonic: once a commit succeeds, the slot can
///   never return to `Pending` or `None`.
/// - The TWL is refreshed to the full `IEDM_KEY_TTL_LEDGERS` window so
///   the committed marker outlives the pending window.
///
/// Returns `true` if the commit was applied.
pub fn commit_idempotency_key(
    env: &Env,
    caller: &Address,
    key: &BytesN<32>,
) -> bool {
    let storage = env.storage().instance();
    let storage_key = idempotency_key(caller, key);

    match storage.get::DataKey, IdempotencyStatus>(&storage_key) {
        Some(IdempotencyStatus::Pending()) => {
            storage.set(&storage_key, &IdempotencyStatus::Committed);
            storage.extend_ttl(&storage_key, IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);
            true
        }
        _ => false,
    }
}

/// Release a pending reservation without committing it.
///
/// This is the explicit rollback path for a caller that reserved a key
/// but failed validation before committing. It must only remove a
/// `Pending` slot owned by the same caller. A `Committed` slot is never
/// released, so a completed batch cannot be erased by a later retry.
///
/// Returns `true` if a pending reservation was released.
pub fn release_idempotency_key(
    env: &Env,
    caller: &Address,
    key: &BytesN<32>,
) -> bool {
    let storage = env.storage().instance();
    let storage_key = idempotency_key(caller, key);

    match storage.get::DataKey, IdempotencyStatus>(&storage_key) {
        Some(IdempotencyStatus::Pending()) => {
            storage.remove(&storage_key);
            true
        }
        _ => false,
    }
}
