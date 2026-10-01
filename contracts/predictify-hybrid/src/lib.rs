//! # predictify-hybrid
//!
//! Soroban smart contract for prediction markets.
//!
//! ## Idempotency
//!
//! `place_bets` accepts a caller-supplied `BytesN<32>` idempotency key.
//! The key is stored in **temporary** storage under
//! `DataKey::PlaceBetsIdem(caller, key)` as a
//! [`bets::BatchReceipt`], with a TTL of
//! [`storage::IDEM_KEY_TTL_LEDGERS`] ledgers (~24 h).  Repeated
//! submissions with the same `(caller, key)` pair are rejected: with
//! `Error::IdempotentBatchAlreadyApplied` when the batch matches the one
//! the token was spent on, and with
//! `Error::IdempotencyKeyReusedWithDifferentBatch` when it does not, so
//! a client can distinguish a harmless duplicate from a token collision.
//! Once the receipt has expired the network has deleted it, so the token
//! may be reused as a fresh batch.
//!
//! Temporary rather than instance storage is deliberate: the contract
//! instance is a single bounded ledger entry, so accumulating one
//! receipt per batch there would eventually exceed `max_entry_size` and
//! disable the contract for every caller.  Persistent storage is avoided
//! because deduplication must *read* the receipt, and an archived
//! persistent entry cannot be read without a paid restore — which would
//! make an expired token permanently unusable instead of reusable.  See
//! [`storage::DataKey`].
//!
//! ## State invariants
//!
//! [`bets`] documents the authorization, validation and state-transition
//! invariants this entry point owns, together with the failure modes
//! that preserve them.

#[no_std]

#[cfg(test)]
mod batch_operations_tests;
mod bets;
mod errors;
mod storage;

#[cfg(test)]
mod batch_operations_tests;
#[cfg(test)]
mod bets_concurrency_tests;
#[cfg(test)]
mod bets_invariants_tests;

pub use bets::{BatchReceipt, Bet, MAX_BETS_PER_BATCH};
pub use errors::Error;
pub use storage::{DataKey, IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_THRESHOLD_LEDGERS};

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
