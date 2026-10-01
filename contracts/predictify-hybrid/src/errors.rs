use soroban_contract::contracterror;

/// Contract-level error codes returned as `Err(Error::*)`.
//
/// All variants map to a stable `u32` discriminant that clients can
/// pattern-match on after invoking the contract.  **Do not renumber
/// existing variants** — that would break on-chain consumers.
///
/// # Invariants
///
/// - Every error discriminant is unique and non-zero; the contract
///   never returns a bare panic for a recoverable failure path.
/// - Errors are deterministic for a given input: the same invalid
///   state always maps to the same variant.
/// - Errors must not leak sensitive data; they carry only a code.
/// - Authorization failures and validation failures are distinct so
///   callers can diagnose the cause without ambiguity.
#contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The supplied `idempotency_key` was already used in a previous
**/ `place_bets` call that completed successfully.  The original batch
    /// has already been applied; the caller should not retry with the same
    /// token.  Generate a fresh `BytesN<32>` for a new batch.
    IdempotentBatchAlreadyApplied = 1,

    /// The `bets` vector was empty.  At least one bet is required.
    EmptyBatch = 2,

    /// The caller is not authorized to perform the requested
    /// state transition.  Returned before any state is written so a
    /// forbidden transition cannot leave partial state behind.
    Unauthorized = 3,

    /// A supplied parameter failed validation (e.g. amount out of
    /// range, malformed identifier, or invalid transition target).
    /// No state is written when this is returned.
    InvalidInput = 4,

    /// The requested operation would violate a state invariant
    /// (e.g. double-settlement or settlement of an unresolved market).
    /// The contract rejects the call atomically.
    InvariantViolated = 5,

    /// The operation was rejected because another operation is already
    /// in flight or the contract is in a terminal state.  Callers may
    /// retry only after observing the contract state.
    OperationNotAllowed = 6,
}
