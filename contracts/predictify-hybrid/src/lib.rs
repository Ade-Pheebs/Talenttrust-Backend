//! # predictify-hybrid
///
/// Soroban smart contract for prediction markets.
///
/// ## Idempotency
///
/// `place_bets` accepts a caller-supplied `BytesN<32>` idempotency key.
/// The key is stored in instance storage under
/// `DataKey::PlaceBetsIdem(caller, key)` with a TTL of
/// [`storage::IDEM_KEY_TTL_LEDGERS`] ledgers (~24 h).  Repeated
/// submissions with the same `(caller, key)` pair are rejected with
/// `Error::IdempotentBatchAlreadyApplied`.
///
/// ## Concurrency and determinism
///
/// Soroban executes contract invocations sequentially within a
/// ledger, and the idempotency guard is the first mutating action of
/// `place_bets`.  This means that even if two identical requests are
/// submitted in the same ledger, the second one observes the first
/// one's committed key and is rejected before any state change.
/// The key is only written after all validation succeeds, so a
/// rejected batch does not consume the key and can be retried with
/// corrected input.

/// ## Concurrency and atomicity
///
/// Soroban executes each contract invocation transactionally and
/// sequentially within a ledger, so two invocations of `place_bets`
/// cannot interleave their storage writes.  The idempotency key is
/// claimed (and the claim is committed) before any bet is applied,
/// so a retry or a duplicate submission of the same batch is
/// deterministically rejected rather than re-applied.  If any bet in
/// the batch fails validation the whole invocation reverts, including
/// the idempotency claim, so a corrected retry with the same key is
/// still allowed.

#[no_std]

mod bets;
mod errors;
mod storage;

#[cfg(test)]
mod batch_operations_tests;
#[cfg(test)]
mod recovery_tests;

use soroban_sdk{contract, contractimpl, Address, BytesN, Env, Vec};

#[contract]
pub struct PredictifyHybrid;

#[contractimpl]
impl PredictifyHybrid {
    /// Submit a batch of bets atomically.
    ///
    /// See [`bets::place_bets`] for full documentation.
    ///
    /// ## Ensured invariants
    ///
    /// - **Idempotency**: a `(caller, idempotency_key)` pair is consumed
    ///   at most once. Repeated or racing submissions return
    ///   [`Error::IdempotentBatchAlreadyApplied`] without mutating state.
    /// - **All-or-nothing**: either every bet in the batch is applied
    ///   or none are; a failed batch does not consume the idempotency
    ///   key, so it can be retried after correction.
    /// - **Authorization**: the caller must authorize the invocation
    ///   before any state change is observable.
    pub fn place_bets(
        env: Env,
        caller: Address,
        bets: Vec<Bet>,
        idempotency_key: BytesN<32>,
    ) -> Result<Void, Error> {
        bets::place_bets(&env, caller, bets, idempotency_key)
    }

    /// Recovery query (#1288): the receipt of the batch applied under
    /// `(caller, idempotency_key)`, or `None` if nothing was applied (or the
    /// key has expired). Read-only and unauthenticated — receipts hold only
    /// counts, totals and a hash of public bet data.
    pub fn get_batch_receipt(
        env: Env,
        caller: Address,
        idempotency_key: BytesN<32>,
    ) -> Option<BatchReceipt> {
        bets::batch_receipt(&env, caller, idempotency_key)
    }

    /// The largest batch `place_bets` accepts ([`MAX_BATCH_SIZE`]), so
    /// clients can split batches without hard-coding the limit.
    pub fn max_batch_size(_env: Env) -> u32 {
        MAX_BATCH_SIZE
    }
}
