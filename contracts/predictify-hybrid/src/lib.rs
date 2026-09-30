//! # predictify-hybrid
///
/// Soroban smart contract for prediction markets.
///
/// ## Idempotency
///
/// `place_bets` accepts a caller-supplied `BytesN<32>`
/// idempotency key. The key is stored in instance storage under
/// `DataKey::PlaceBetsIdem(caller, key)` with a TTL of
/// [`storage::IDEM_KEY_TTL_LEDGERS`] ledgers (~24 h).  Repeated
/// submissions with the same `(caller, key)` pair are rejected with
/// `Error::IdempotentBatchAlreadyApplied`.

/// ## State invariants
///
/// This crate owns the following invariants for the batch-operations

/// entry points. They are enforced in [`bets::place_bets`] and are
/// exercised by the focused tests in `batch_operations_tests.rs`.
///
/// 1. **Atomicity**: a batch either applies in full or not at all.
///    Validation is performed before any state mutation, and the
///    idempotency marker is written only after the batch has been
///    fully applied.
/// 2. **Idempotency**: for a given `(caller, key)` pair, at most one
///    batch is applied. Repeated or concurrent submissions are
///    rejected with `Error::IdempotentBatchAlreadyApplied`.
/// 3. **Authorization**: the caller must have authorized the
///    invocation before any state is read or written.
/// 4. **Validation**: every bet in the batch must pass the same
///    validation rules as a single-bet submission; invalid batches
///    are rejected without mutating state.
/// 5. **Boundaries**: empty batches and batches exceeding the
///    configured maximum are rejected deterministically.

#[no_std]

mod bets;
mod errors;
mod storage;

pub use bets::Bet;
pub use errors::Error;
pub use storage::{DataKey, IDEM_KEY_TTL_LEDGERS};

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Vec};

#[contract]
pub struct PredictifyHybrid;

#[contractimpl]
impl PredictifyHybrid {
    /// Submit a batch of bets atomically.
    ///
    /// See [`bets::place_bets`] for full documentation.
    ///
/// # Errors
///
/// - `Error::IdempotentBatchAlreadyApplied` if the `(caller, key)` has
///   already been used.
/// - `Error::EmptyBatch` if `bets` is empty.
/// - `Error::BatchTooLarg` if `bets.len()` exceeds the maximum.
/// - `Error::InvalidBet` for any per-bet validation failure.
    pub fn place_bets(
        env: Env,
        caller: Address,
        bets: Vec<Bet>,
        idempotency_key: BytesN<32>,
    ) -> Result<(), Error> {
        bets::place_bets(&env, caller, bets, idempotency_key)
    }
}
