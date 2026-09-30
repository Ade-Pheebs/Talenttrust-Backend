use soroban_sdk::contracterror;

/// Contract-level error codes returned as `Err(Error::*)`.
///
/// All variants map to a stable `u32` discriminant that clients can
/// pattern-match on after invoking the contract.  **Do not renumber
/// existing variants** — that would break on-chain consumers.  New
/// variants must take the next free discriminant.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The supplied `idempotency_key` was already used in a previous
    /// `place_bets` call that completed successfully.  The original batch
    /// has already been applied; the caller should not retry with the same
    /// token.  Generate a fresh `BytesN<32>` for a new batch.
    IdempotentBatchAlreadyApplied = 1,

    /// The `bets` vector was empty.  At least one bet is required.
    EmptyBatch = 2,

    /// The `bets` vector exceeded `MAX_BETS_PER_BATCH`.
    ///
    /// Returned before any state is written, so the caller may split the
    /// batch and resubmit with the *same* idempotency key.
    BatchTooLarge = 3,

    /// A [`crate::bets::Bet`] carried a non-positive `amount`.
    ///
    /// A zero amount is a no-op that would still consume an idempotency
    /// key, and a negative amount would credit one side of a market
    /// while debiting the other.  Both are rejected before anything is
    /// recorded, so the same key stays reusable.
    InvalidBetAmount = 4,

    /// A [`crate::bets::Bet`] carried `market_id == 0`.
    ///
    /// `0` is reserved as the "no market" sentinel; stake recorded
    /// against it could never be resolved or paid out.
    InvalidMarketId = 5,

    /// The sum of the batch's `amount` values does not fit in an `i128`.
    ///
    /// The release profile disables debug assertions, so an unchecked sum
    /// would wrap and record a negative total.  The batch is rejected
    /// instead, and the same key stays reusable.
    BatchAmountOverflow = 6,
}
