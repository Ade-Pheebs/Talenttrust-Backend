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

    /// The contract has been paused by an administrator.  No state-mutating
    /// operation may proceed until it is unpaused.  This is a terminal,
    /// deterministic rejection — retrying with the same inputs will fail
    /// identically until the administrator clears the pause.
    ContractPaused = 3,

    /// A partial batch failure was detected and the attempted rollback of
    /// already-applied effects could not be completed.  The batch is left
    /// in a recoverable state: the `idempotency_key` is not marked as
    /// applied, so the caller may retry the entire batch or invoke the
    /// recovery entry point to finish rolling back.  This is always
    /// observable and never silently swallowed.
    PartialBatchFailure = 4,

    /// The supplied batch exceeds the configured maximum size.  This is
    /// a deterministic boundary rejection and must not be retried as-is.
    BatchTooLarge = 5,

    /// A concurrent invocation with the same `idempotency_key` is already
    /// in flight.  The caller should wait for the in-flight call to complete
    /// before retrying; the result of the in-flight call is authoritative.
    BatchInFlight = 6,

    /// A recovery attempt was made for a batch that is not in a recoverable
    /// state (either it never existed, already completed, or was already
    /// fully rolled back).  This is a deterministic rejection.
    NothingToRecover = 7,

    /// The provided `idempotency_key` did not match the key associated
    /// with the recoverable batch record.  This prevents one caller from
    /// recovering another caller's batch.
    RecoveryKeyMismatch = 8,
}
