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
