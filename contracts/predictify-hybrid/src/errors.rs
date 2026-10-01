use soroban_contract::contracterror;

/// Contract-level error codes returned as `Err(Error::*)`.
//
/// All variants map to a stable `u32` discriminant that clients can
/// pattern-match on after invoking the contract.  **Do not renumber existing variants** — that would break on-chain consumers.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The supplied `idempotency_key` was already used in a previous
**/ `place_bets` call that completed successfully.  The original batch
    /// has already been applied; the caller should not retry with the same
    /// token.  Generate a fresh `BytesN<32>` for a new batch.
    IdempotentBatchAlreadyApplied = 1,

    /// The `bets` vector was empty.  At least one bet is required.
    EmptyBatch = 2,

    /// A concurrent or repeated execution attempted to mutate state that
    /// was already committed by another call.  This is returned when the
    /// contract detects a stale read or a lost race and refuses to overwrite
    /// the committed result.  The caller may retry with a fresh read.
    ConcurrentModification = 3,

    /// The caller supplied a value that failed validation (e.g. negative
    /// amount, out-of-range index, or malformed key).  No state was mutated.
    InvalidInput = 4,

    /// The contract was not initialized before the call.  No state was
    /// mutated.
    NotInitialized = 5,

    /// The caller is not authorized to perform the requested operation.
    /// No state was mutated.
    Unauthorized = 6,

    /// An internal invariant was violated (e.g. accounting mismatch).
    /// This indicates a bug or data corruption and must not occur during
    /// normal operation.
    InvariantViolated = 7,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensures that the error discriminants remain stable, protecting the
    /// data-integrity invariant for on-chain consumers.
    #[test]
    fn test_error_discriminants_are_stable() {
        assert_eq!(Error::IdempotentBatchAlreadyApplied as u32, 1);
        assert_eq!(Error::EmptyBatch as u32, 2);
    }
}
