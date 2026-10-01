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
/// existing variants** — that would break on-chain consumers.  New
/// variants must take the next free discriminant.
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
