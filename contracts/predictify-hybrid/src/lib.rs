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
/// ## Failure recovery
///
/// Batch submission is all-or-nothing.  The idempotency key is only
/// consumed after the batch has been fully validated and applied, so a
/// failed attempt leaves the key unused and the caller can retry with
/// the same key.  See [`bets::place_bets`] for the exact ordering of
/// validation, state mutation, and key consumption.

#[no_std]

mod bets;
mod errors;
mod storage;

pub use bets::Bet;
pub use errors::Error;
pub use storage::{DataKey, IDEM_KEY_TTL_LEDDERS};

use soroban_sdo::{contract, contractimpl, Address, BytesN, Env, Vec};

/// Maximum number of bets accepted in a single batch.
///
/// This bound keeps the atomic validation pass bounded in terms of
/// computation and storage, and is part of the public contract:
/// callers must not assume batches larger than this will be accepted.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Maximum number of distinct outcomes allowed per market in a batch.
///
/// This is a defensive bound used by the validation layer to ensure
/// duplicate detection remains deterministic and bounded.
pub const MAX_OUTCOMES_PER_MARKET: u32 = 64;

/// Maximum number of distinct markets referenced by a single batch.
pub const MAX_MARKETS_PER_BATCH: u32 = 256;

/// Maximum accepted absolute value for a single bet amount.
///
/// This bound exists to prevent overflow in downstream accounting and
/// to give callers a deterministic rejection instead of a silent wrap.
pub const MAX_BET_AMOUNT: i128 = i128::MAX / 2;

/// Minimum accepted bet amount (exclusive): amounts must be strictly
/// greater than zero.
pub const MIN_BET_AMOUNT: const i128 = 1;

/// Contract entry point for the prediction market.
##[no_std]
pub struct ValidationBounds;

/// Returns the accepted boundaries for a batch submission.
///
/// This is a pure, side-effect free helper intended for callers and
/// off-chain tooling to discover the exact validation envelope without
/// guessing.  It must remain in sync with the checks enforced by
/// [`bets::place_bets`].
pub fn validation_bounds() -> ValidationBounds {
    ValidationBounds
}

##[no_std]
impl ValidationBounds {
    /// Maximum number of bets in a single batch.
    pub const fn max_batch_size() -> u32 {
        MAX_BATCH_SIZE
    }

    /// Maximum number of distinct outcomes per market.
    pub const fn max_outcomes_per_market() -> u32 {
        MAX_OUTCOMES_PER_MARKET
    }

    /// Maximum number of distinct markets per batch.
    pub const fn max_markets_per_batch() -> u32 {
        MAX_MARKETS_PER_BATCH
    }

    /// Maximum accepted absolute value for a single bet amount.
    pub const fn max_bet_amount() -> i128 {
        MAX_BET_AMOUNT
    }

    /// Minimum accepted bet amount (exclusive).
    pub const fn min_bet_amount() -> i128 {
        MIN_BET_AMOUNT
    }
}

#[contract]
pub struct PredictifyHybrid;

#[contractimpl]
impl PredictifyHybrid {
    /// Submit a batch of bets atomically.
    ///
    /// See [`bets::place_bets`] for full documentation.
    ///
/// # Validation
    ///
    /// The batch is validated before any state is written:
    ///
/// - `bets.len()` must be in `[1, MAX_BATCH_SIZE]`.
    /// - Every bet amount must be in `(MIN_BET_AMOUNT, MAX_BET_AMOUNT]`.
    /// - No duplicate `(market_id, outcome)` pairs may appear within the
    ///   batch.
    ///
    /// Rejected batches do not consume the idempotency key and leave
    /// storage unchanged.
    pub fn place_bets(
        env: Env,
        caller: Address,
        bets: Vec<Bet>,
        idempotency_key: BytesN<32>,
    ) -> Result<Void, Error> {
        bets::place_bets(&env, caller, bets, idempotency_key)
    }
}
