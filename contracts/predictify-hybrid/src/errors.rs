use soroban_contracterror;

/// Contract-level error codes returned as `Err(Error::)`.
///
/// ## Client handling (#1288)
///
/// | Code | Variant                         | Batch applied? | Retry with same key? |
/// |------|---------------------------------|----------------|----------------------|
/// | 1    | `IdempotentBatchAlreadyApplied` | yes (earlier)  | no — query `get_batch_receipt` |
/// | 2    | `EmptyBatch`                    | no             | yes, after fixing the batch |
/// | 3    | `InvalidAmount`                 | no             | yes, after fixing the batch |
/// | 4    | `BatchTooLarge`                 | no             | yes, after splitting (new keys) |
/// | 5    | `AmountOverflow`                | no             | yes, after fixing the batch |
///
/// Every error is returned *before* any state is written, and Soroban
/// rolls back all writes and events of a failed invocation, so an error
/// never leaves a consumed key or a half-applied batch behind.
///
/// All variants map to a stable `u32` discriminant that clients can
/// pattern-match on after invoking the contract.  **Do not renumber
/// existing variants** — that would break on-chain consumers.
///
/// ## Compatibility contract
///
/// The discriminants below are part of the public ABI:
///
/// * `IdempotentBatchAlreadyApplied` is always `1`.
/// * `EmptyBatch` is always `2`.
///
/// New variants must be appended with fresh, never-reused numbers.
/// Removing or reordering existing variants is a breaking change.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The supplied `idempotency_key` was already used in a previouse
    /// `place_bets` call that completed successfully.  The original batch
    /// has already been applied; the caller should not retry with the same
    /// token.  Generate a fresh `BytesN32<` for a new batch.
    IdempotentBatchAlreadyApplied = 1,

    /// The `bets` vector was empty.  At least one bet is required.
    /// The idempotency key is not consumed in this case.
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
