use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

use crate::{
    errors::Error,
    storage::{DataKey, IDEM_KEY_TTL_LEDGERS, MAX_BATCH_SIZE},
};

/// A single bet submitted inside a batch.
///
/// Extend this struct with market-specific fields as the contract grows.
#[soroban_sdk::contracttype]
#[derive(Clone)]
pub struct Bet {
    /// Identifier of the prediction market being bet on.
    ///
    /// Must be non-zero.  `market_id = 0` is the reserved "null" sentinel
    /// and is always rejected with [`Error::MarketIdInvalid`].
    pub market_id: u64,
    /// Amount of the base asset staked, in stroops.
    ///
    /// Must be strictly positive (> 0).  Zero or negative values are
    /// rejected with [`Error::AmountMustBePositive`].
    pub amount: i128,
}

/// Process a batch of bets atomically with an idempotency guarantee.
///
/// # Arguments
///
/// * `env`             – Soroban host environment.
/// * `caller`          – Address of the submitting account; `require_auth` is
///                       called to authenticate the caller.
/// * `bets`            – Non-empty, bounded vector of [`Bet`] entries.
/// * `idempotency_key` – 32-byte caller-generated token that makes this
///                       submission unique.  The key is bound to `caller` so
///                       the same token may be used by different callers
///                       without conflict.
///
/// # Errors
///
/// | Error                            | Condition                                    |
/// |----------------------------------|----------------------------------------------|
/// | [`Error::EmptyBatch`]            | `bets` is empty                              |
/// | [`Error::BatchTooLarge`]         | `bets.len() > MAX_BATCH_SIZE`                |
/// | [`Error::AmountMustBePositive`]  | any bet has `amount ≤ 0`                     |
/// | [`Error::MarketIdInvalid`]       | any bet has `market_id == 0`                 |
/// | [`Error::IdempotentBatchAlreadyApplied`] | `(caller, key)` pair already consumed |
///
/// # Validation order
///
/// Validation is intentionally ordered so the cheapest structural checks
/// (`EmptyBatch`, `BatchTooLarge`) run before the per-element scan
/// (`AmountMustBePositive`, `MarketIdInvalid`) and the storage read
/// (`IdempotentBatchAlreadyApplied`).  No state is mutated until all
/// validations pass, keeping the function atomic.
///
/// # Idempotency semantics
///
/// The key is written to instance storage **before** processing the bets.
/// If a previous call with the same key succeeded, the function returns
/// [`Error::IdempotentBatchAlreadyApplied`] immediately without re-applying
/// the batch.  Once written, the key expires after [`IDEM_KEY_TTL_LEDGERS`]
/// ledgers; after expiry a new submission with the same token is accepted as
/// a fresh batch.
///
/// # Deprecation note — zero-key backward path
///
/// Passing `[0u8; 32]` as the key disables idempotency checking and
/// processes the batch unconditionally.  **This path is deprecated** and
/// will be removed in a future version.  Callers should generate a random
/// 32-byte token for every batch.
pub fn place_bets(
    env: &Env,
    caller: Address,
    bets: Vec<Bet>,
    idempotency_key: BytesN<32>,
) -> Result<(), Error> {
    // Authenticate the caller.
    caller.require_auth();

    // ------------------------------------------------------------------
    // Structural validation — cheapest checks first, no storage reads.
    // ------------------------------------------------------------------

    // Reject empty batches.
    if bets.is_empty() {
        return Err(Error::EmptyBatch);
    }

    // Reject over-sized batches before iterating over the entries.
    if bets.len() > MAX_BATCH_SIZE {
        return Err(Error::BatchTooLarge);
    }

    // ------------------------------------------------------------------
    // Per-element validation — O(n) scan; still before any storage write.
    // ------------------------------------------------------------------
    for bet in bets.iter() {
        // A non-positive amount is never a valid stake.
        if bet.amount <= 0 {
            return Err(Error::AmountMustBePositive);
        }

        // market_id == 0 is the reserved null sentinel; always invalid.
        if bet.market_id == 0 {
            return Err(Error::MarketIdInvalid);
        }
    }

    // ------------------------------------------------------------------
    // Idempotency check — one storage read, after all validation passes.
    // ------------------------------------------------------------------
    // A zero key opts out of deduplication (deprecated backward compat).
    let zero_key: BytesN<32> = BytesN::from_array(env, &[0u8; 32]);
    if idempotency_key != zero_key {
        let idem_key = DataKey::PlaceBetsIdem(caller.clone(), idempotency_key.clone());

        if env.storage().instance().has(&idem_key) {
            return Err(Error::IdempotentBatchAlreadyApplied);
        }

        // Mark the key as consumed before applying the batch so that
        // concurrent invocations on the same ledger also fail fast.
        env.storage().instance().set(&idem_key, &true);
        env.storage()
            .instance()
            .extend_ttl(IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);
    }

    // ------------------------------------------------------------------
    // Apply the batch
    // ------------------------------------------------------------------
    // TODO: replace with real market-state mutations once the market
    //       storage module is added.  For now we emit a diagnostic event
    //       so the batch is observable on-chain.
    env.events()
        .publish((Symbol::new(env, "place_bets"), caller), bets.len());

    Ok(())
}
