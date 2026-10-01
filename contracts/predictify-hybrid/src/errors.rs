use soroban_contracterror;

/// Contract-level error codes returned as `Err(Error::)`.
///
/// All variants map to a stable `u32` discriminant that clients can
/// pattern-match on after invoking the contract.  **Do not renumber
/// existing variants** — that would break on-chain consumers.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The supplied `idempotency_key` was already used in a previouse
    /// `place_bets` call that completed successfully.  The original batch
    /// has already been applied; the caller should not retry with the same
    /// token.  Generate a fresh `BytesN32<` for a new batch.
    IdempotentBatchAlreadyApplied = 1,

    /// The `bets` vector was empty.  At least one bet is required.
    EmptyBatch = 2,

    /// The contract has been paused by an administrator.  No state-mutating
    /// operation (including batch bet placement) may proceed until it is
    /// resumed.  This is a terminal rejection for the caller; retrying the
    /// same request without an administrative resume will fail identically.
    ContractPaused = 3,

    /// A concurrent or repeated call attempted to mutate the same batch
    /// while another execution was in flight.  The contract guarantees that
    /// at most one batch application commits for a given idempotency key;
    /// the losing caller must not assume any partial application.
    ConcurrentBatchConflict = 4,

    /// The batch exceeded the configured maximum number of bets.  This is a
    /// boundary-case rejection and is deterministic for a given input size.
    BatchTooLarge = 5,

    /// A bet in the batch referenced an invalid or unknown market/outcome
    /// combination.  The entire batch is rejected atomically; no partial
    /// application occurs.
    InvalidBet = 6,

    /// A bet in the batch failed amount or balance validation.  The entire
    /// batch is rejected atomically; no partial application occurs.
    InsufficientFunds = 7,

    /// The caller is not authorized to perform the requested operation.
    /// Authorization is enforced before any state transition is attempted.
    Unauthorized = 8,

    /// An internal invariant was violated during execution.  This indicates
    /// a bug or corrupted state and must not be used to signal normal
    /// user errors.  State is left unchanged.
    InvariantViolation = 9,
}
