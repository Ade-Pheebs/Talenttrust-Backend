use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

use crate::{
    errors::Error,
    storage::{DataKey, IDEM_KEY_TTL_LEDGERS},
};

/// A single bet submitted inside a batch.
///
/// Extend this struct with market-specific fields as the contract grows.
#[soroban_sdk::contracttype]
#[derive(Clone)]
pub struct Bet {
    /// Identifier of the prediction market being bet on.
    pub market_id: u64,
    /// Amount of the base asset staked, in stroops.
    pub amount: i128,
}

/// Maximum number of bets allowed in a single batch submission.
///
/// Bounds the amount of work performed per invocation so that a single
/// transaction cannot exhaust the ledger budget or produce an unbounded
/// state transition.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Process a batch of bets atomically with an idempotency guarantee.
///
/// # Arguments
///
/// * `env`             – Soroban host environment.
/// * `caller`          – Address of the submitting account; `require_auth` is
///                       called to authenticate the caller.
/// * `bets`            – Non-empty vector of [`Bet`] entries.
/// * `idempotency_key` – 32-byte caller-generated token that makes this
///                       submission unique.  The key is bound to `caller` so
///                       the same token may be used by different callers
///                       without conflict.
///
/// # Errors
///
/// * [`Error::EmptyBatch`]                   – `bets` is empty.
/// * [`Error::BatchTooLarge`]                – `bets` exceeds [`MAX_BATCH_SIZE`].
/// * [`Error::InvalidBetAmount`]             – a bet has a non-positive amount.
/// * [`Error::DuplicateBet`]                 – the same `market_id` appears
///                                              more than once in the batch.
/// * [`Error::IdempotentBatchAlreadyApplied`] – the `(caller, idempotency_key)`
///                                              pair has already been consumed.
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
///
/// # Concurrency invariants
///
/// * The `(caller, idempotency_key)` marker is written to instance storage
///   before any batch state is mutated, so a re-entrant or racing call on
///   the same ledger observes the marker and fails fast with
///   [`Error::IdempotentBatchAlreadyApplied`].
/// * The marker's TTL is extended on every successful write so the
///   deduplication window is at least [`IDEM_KEY_TTL_LEDGERS`] ledgers from
///   the most recent submission.
pub fn place_bets(
    env: &Env,
    caller: Address,
    bets: Vec<Bet>,
    idempotency_key: BytesN<32>,
) -> Result<(), Error> {
    // Authenticate the caller.
    caller.require_auth();

    // Snapshot the batch length once so downstream logic and events cannot
    // observe a mutated vector (defensive against future re-entrancy).
    let batch_len = bets.len();

    // Reject empty batches early.
    if bets.is_empty() {
        return Err(Error::EmptyBatch);
    }

    // Enforce the upper bound on batch size.
    if bets.len() > MAX_BATCH_SIZE {
        return Err(Error::BatchTooLarge);
    }

    // Validate each bet: positive amount and no duplicate market ids.
    for i in 0..bets.len() {
        let bet = bets.get(i).unwrap();
        if bet.amount <= 0 {
            return Err(Error::InvalidBetAmount);
        }
        for j in (i + 1)..bets.len() {
            if bets.get(j).unwrap().market_id == bet.market_id {
                return Err(Error::DuplicateBet);
            }
        }
    }

    // ------------------------------------------------------------------
    // Idempotency check
    // ------------------------------------------------------------------
    // A zero key opts out of deduplication (deprecated backward compat).
    let zero_key: BytesN<32> = BytesN::from_array(env, &[0u8; 32]);
    // Track whether we consumed an idempotency marker so we can roll it
    // back if a later step fails, keeping retries idempotent.
    let mut consumed_idem: Option<DataKey> = None;
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
        consumed_idem = Some(idem_key);
    }

    // ------------------------------------------------------------------
    // Apply the batch
    // ------------------------------------------------------------------
    // TODO: replace with real market-state mutations once the market
    //       storage module is added.  For now we emit a diagnostic event
    //       so the batch is observable on-chain.
    //
    // Any failure raised by future batch-application logic must not leave
    // the idempotency marker behind, otherwise a legitimate retry would be
    // rejected as a duplicate.  We therefore guard the marker with an
    // explicit rollback on error.
    let apply_result: Result<(), Error> = (|| {
        env.events()
            .publish((Symbol::new(env, "place_bets"), caller.clone()), batch_len);
        Ok(())
    })();

    if let Err(err) = apply_result {
        if let Some(key) = consumed_idem {
            env.storage().instance().remove(&key);
        }
        return Err(err);
    }

    Ok(())
}
