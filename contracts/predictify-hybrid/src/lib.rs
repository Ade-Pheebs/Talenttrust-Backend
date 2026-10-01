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
/// ## Validation boundaries
+///
/// This crate defines the authoritative validation boundaries for the
/// `place_bets` entry point. The boundaries are enforced in a fixed
/// order so that rejection is deterministic regardless of the caller:
///
/// 1. Authorization — the caller must have authorized the
///    invocation. This is checked first because it is the only
///    security boundary that cannot be recovered from.
/// 2. Batch shape — the batch must be non-empty and must not
///    exceed [`MAX_BATCH_SIZE`]. This bounds work and prevents
///    unrecoverable gas exhaustion.
/// 3. Per-bet fields — each bet must carry a positive amount and a
///    non-empty outcome.
/// 4. Deduplication — the caller must not have already applied
///    the same idempotency key.
///
/// ## Invariants
+///
/// - The idempotency record is written only after all validation
///   passes, and is written before any state mutation so that a
///   partial failure never leaves a batch half-applied.
/// - Rejection order is fixed: auth → shape → fields → duplicate.
///   Two invocations with the same inputs always produce the
///   same result.
/// - All rejections are expressed as a typed [`Error`] and never
///   as a panic, except for the authorization check which is
///   delegated to Soroban's `Address::require_auth`.

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
