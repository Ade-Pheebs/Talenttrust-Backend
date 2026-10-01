//! # predictify-hybrid
//!
//! Soroban smart contract for prediction markets.
//!
//! ## Idempotency
//!
//! `place_bets` accepts a caller-supplied `BytesN<32>` idempotency key.
//! The key is stored in temporary storage under
//! `DataKey::PlaceBetsIdem(caller, key)` with a TTL of
//! [`storage::IDEM_KEY_TTL_LEDGERS`] ledgers (~24 h).  Repeated
//! submissions with the same `(caller, key)` pair are rejected with
//! `Error::IdempotentBatchAlreadyApplied`.

#[no_std]

mod bets;
mod errors;
mod storage;

pub use bets::Bet;
pub use errors::Error;
pub use storage::{DataKey, IDEM_KEY_TTL_LEDGERS};

use soroban_sdk::{contract, contractimpl, Address, BytesN<32>, Env, Vec};

/// Maximum number of bets accepted in a single ``place_bets``b call.
///
/// This is a hard boundary that protects the contract from
/// unbounded work and from gas exhaustion attacks. It is part of
/// the public contract surface and must not be changed without a
/// compatibility plan.
pub const MAX_BATCH_SIZE: u32 = 32;

#[contract]
pub struct PredictifyHybrid;

#[contractimpl]
impl PredictifyHybrid {
    /// Submit a batch of bets atomically.
///
    /// See [`bets::place_bets`] for full documentation. The
    /// validation boundaries are documented at the crate root and
/// enforced in ``bets::place_bets``.
    pub fn place_bets(
        env: Env,
        caller: Address,
        bets: Vec<Bet>,
        idempotency_key: BytesN<32>,
    ) -> Result<(), Error> {
        bets::place_bets(&env, caller, bets, idempotency_key)
    }
}

#[cfg(test)]
mod batch_operations_tests;
