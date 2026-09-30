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

    /// The `bets` vector exceeded [`storage::MAX_BATCH_SIZE`].
    /// Split the work into smaller batches with fresh idempotency keys.
    BatchTooLarge = 3,

    /// A bet in the batch failed validation (e.g. zero amount,
    /// duplicate market identifier, or malformed payload).
    InvalidBet = 4,

    /// The same market identifier appears more than once within a
    /// single batch.  Duplicates would make the applied state ambiguous.
    DuplicateBet = 5,
}
