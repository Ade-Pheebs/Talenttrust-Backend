use soroban_sdk::contracterror;

/// Contract-level error codes returned as `Err(Error::*)`.
///
/// All variants map to a stable `u32` discriminant that clients can
/// pattern-match on after invoking the contract.  **Do not renumber
/// existing variants** — that would break on-chain consumers.
///
/// # Invariants
///
/// - Every error discriminant is unique and non-zero.
/// - Error codes are append-only: new variants must use fresh values.
/// - Validation failures return a deterministic code for a given input
///   shape, so retries and concurrent calls observe the same result.
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

    /// The `bets` vector exceeded the maximum allowed batch size.
    /// Oversized batches are rejected before any state mutation so that
    /// a partial application cannot occur.
    BatchTooLarge = 3,

    /// A bet entry contained a zero or negative amount.  Amounts are
    /// required to be strictly positive.
    InvalidAmount = 4,

    /// A duplicate market identifier was found within a single batch.
    /// Deduplication is enforced before any state transition.
    DuplicateMarket = 5,

    /// A market identifier was not recognized by the contract.
    UnknownMarket = 6,

    /// The contract has not been initialized yet.
    NotInitialized = 7,

    /// The contract has already been initialized.
    AlreadyInitialized = 8,

    /// The caller is not authorized to perform the requested operation.
    Unauthorized = 9,

    /// An internal invariant was violated.  This indicates a bug in the
    /// contract rather than bad input and should never be observed in
    /// normal operation.
    InvariantViolated = 10,
}
