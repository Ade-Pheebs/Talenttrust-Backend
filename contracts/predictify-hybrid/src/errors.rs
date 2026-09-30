use soroban_sdk::contracterror;

/// Contract-level error codes returned as `Err(Error::*)`.
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
    /// The supplied `idempotency_key` was already used in a previous
    /// `place_bets` call that completed successfully.  The original batch
    /// has already been applied; the caller should not retry with the same
    /// token.  Generate a fresh `BytesN<32>` for a new batch.
    IdempotentBatchAlreadyApplied = 1,

    /// The `bets` vector was empty.  At least one bet is required.
    /// The idempotency key is not consumed in this case.
    EmptyBatch = 2,
}
