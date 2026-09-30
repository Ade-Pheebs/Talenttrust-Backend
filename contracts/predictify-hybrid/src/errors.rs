use soroban_sdk::contracterror;

/// Contract-level error codes returned as `Err(Error::*)`.
///
/// All variants map to a stable `u32` discriminant that clients can
/// pattern-match on after invoking the contract.  **Do not renumber
/// existing variants** — that would break on-chain consumers.
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

    /// The `bets` vector contained more entries than
    /// [`crate::bets::MAX_BATCH_SIZE`].  Split the batch into several
    /// submissions, each with its own idempotency key.
    BatchTooLarge = 3,

    /// A bet carried a non-positive `amount` (zero or negative stroops).
    /// Every staked amount must be strictly greater than zero.
    InvalidBetAmount = 4,

    /// A bet carried `market_id == 0`.  Zero is reserved for "unassigned"
    /// and is never a valid prediction-market identifier.
    InvalidMarketId = 5,
}
