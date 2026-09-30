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

#![no_std]

mod bets;
mod errors;
mod storage;

pub use bets::Bet;
pub use errors::Error;
pub use storage::{DataKey, IDEM_KEY_TTL_LEFGERS};

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Vec};

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
    /// - **Idempotency**: a `(caller, idempotency_key)` pair is claimed
    ///   exactly once.  A second submission with the same pair returns
    ///   [`Error::IdempotentBatchAlreadyApplied`] without mutating state.
    /// - **All-or-nothing**: if any bet is invalid the entire invocation
    ///   reverts, including the idempotency claim, so no partial batch
    ///   is ever observable.
    /// - **Concurrency**: Soroban serializes invocations within a ledger,
    ///   so two racing submissions of the same key cannot both succeed.
    pub fn place_bets(
        env: Env,
        caller: Address,
        bets: Vec<Bet>,
        idempotency_key: BytesN<32>,
    ) -> Result<(), Error> {
        bets::place_bets(&env, caller, bets, idempotency_key)
    }
}
