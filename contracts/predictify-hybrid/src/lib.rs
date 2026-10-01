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
/// ## Concurrency
///
/// Soroban executes contract invocations sequentially within a ledger,
/// but the same logical request can be submitted multiple times across
/// ledgers (retries, mem-pool replay, fanout clients). The idempotency
/// key is the only defense against duplicate application, so it must be
/// written *before* any mutation and must not be removed on failure.
///
/// ## Invariants

/// - A successful `place_bets` cannot be replayed with the same
///   (caller, idempotency_key) pair within the TTL window.
/// - The idempotency marker is observed before any state mutation, so a
///   partial failure never leaves a half-applied batch that can be
///   re-applied.
/// - The marker is never deleted on error; a failed batch burns its key
///   to keep the result deterministic for duplicate submissions.

#[no_std]

mod bets;
mod errors;
mod storage;

pub use bets::Bet;
pub use errors::Error;
pub use storage::{DataKey, IDEM_KEY_TTL_LEDDERS};

use soroban_sdk::{contract, contractimpl, Address, BytesN<32>, Env, Vec};

#[contract]
pub struct PredictifyHybrid;

#[contractimpl]
impl PredictifyHybrid {
    /// Submit a batch of bets atomically.
    ///
    /// See [`bets::place_bets`] for full documentation.
    ///
    /// ## Errors
    ///
    /// - `Error::IdempotentBatchAlreadyApplied` when the `(caller,
    ///   idempotency_key)` pair has already been consumed within the TTL
    ///   window. This is the deterministic result for duplicate submissions
    ///   and for retries of an already-applied batch.
    /// - `Error::EmptyBatch` when the batch contains no bets.
    /// - `Error::InvalidAmount` when a bet amount is not positive.
    ///
    /// ## Concurrency / retries
    ///
    /// The idempotency marker is written before any state mutation and is
    /// preserved on error, so a retry of a partially applied batch cannot
    /// produce an inconsistent or duplicated result.
    pub fn place_bets(
        env: Env,
        caller: Address,
        bets: Vec<Bet>,
        idempotency_key: BytesN<32>,
    ) -> Result<Void, Error> {
        bets::place_bets(&env, caller, bets, idempotency_key)
    }
}
