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

    /// The caller did not authorize this invocation.  Returned when the
    /// `Address` auth check fails.  This is distinct from `IdempotentBatchAlreadyApplied`
    /// so clients can tell authorization failures apart from replays.
    Unauthorized = 3,

    /// The contract has not been initialized yet.  Returned by entry
    /// points that require contract-level configuration to be set up.
    NotInitialized = 4,

    /// The contract has already been initialized.  Re-initialization is
    /// rejected to keep state deterministic and prevent configuration
    /// drift.
    AlreadyInitialized = 5,

    /// A generic invariant violation was detected (e.g. a storage
    /// consistency check failed).  This is a defensive error and indicates
    /// a bug or external tampering; it is not expected during normal
    /// operation.
    InvariantViolation = 6,
}
