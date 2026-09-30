use soroban_sdk::{Address, BytesN, Env, Vec};

use crate::{
    errors::Error,
    storage::{DataKey, IDEM_KEY_TTL_LEDGERS, INSTANCE_TTL_LEDGERS},
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

/// Process a batch of bets atomically with an idempotency guarantee.
///
/// # Arguments
///
/// * `env` – Soroban host environment.
/// * `caller` – Address of the submitting account; `require_auth` is called
///   to authenticate the caller.
/// * `bets` – Non-empty vector of [`Bet`] entries.
/// * `idempotency_key` – 32-byte caller-generated token that makes this
///   submission unique.  The key is bound to `caller` so the same token may be
///   used by different callers without conflict.
///
/// # Errors
///
/// * [`Error::EmptyBatch`] – `bets` is empty.
/// * [`Error::IdempotentBatchAlreadyApplied`] – the `(caller, idempotency_key)`
///   pair has already been consumed.
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

    // Reject empty batches early.
    if bets.is_empty() {
        return Err(Error::EmptyBatch);
    }

    // ------------------------------------------------------------------
    // Idempotency check
    // ------------------------------------------------------------------
    // A zero key opts out of deduplication (deprecated backward compat).
    let zero_key: BytesN<32> = BytesN::from_array(env, &[0u8; 32]);
    if idempotency_key != zero_key {
        let idem_key = DataKey::PlaceBetsIdem(caller.clone(), idempotency_key.clone());
        let idem_ledger_key = DataKey::PlaceBetsIdemLedger(caller.clone(), idempotency_key.clone());
        let now = env.ledger().sequence();

        if env.storage().instance().has(&idem_key) {
            // Instance storage shares the contract instance's TTL entry, so a
            // consumed key cannot simply be evicted when its own window
            // elapses: the window has to be enforced in contract code from the
            // ledger recorded next to the sentinel.
            let consumed_at = env
                .storage()
                .instance()
                .get::<DataKey, u32>(&idem_ledger_key);

            match consumed_at {
                // A sentinel with no recorded ledger was written by an older
                // contract version that stored only `true`. Treat it as a
                // durable replay guard: an upgrade must never make a token
                // that was already consumed replayable again.
                None => return Err(Error::IdempotentBatchAlreadyApplied),

                // Still inside the replay window.
                Some(consumed_at) if now < consumed_at.saturating_add(IDEM_KEY_TTL_LEDGERS) => {
                    return Err(Error::IdempotentBatchAlreadyApplied)
                }

                // The window has elapsed: drop the stale sentinel and fall
                // through so the batch is accepted as a fresh submission.
                Some(_) => {
                    env.storage().instance().remove(&idem_key);
                    env.storage().instance().remove(&idem_ledger_key);
                }
            }
        }

        // Mark the key as consumed before applying the batch so that
        // concurrent invocations on the same ledger also fail fast.
        env.storage().instance().set(&idem_key, &true);
        env.storage().instance().set(&idem_ledger_key, &now);

        // Keep the *instance* entry alive well past the replay window; using
        // the idempotency window here would archive the contract at exactly
        // the moment the newest key expires.
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_LEDGERS, INSTANCE_TTL_LEDGERS);
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

// Symbol is used above; import it here to keep the use-site clean.
use soroban_sdk::Symbol;
