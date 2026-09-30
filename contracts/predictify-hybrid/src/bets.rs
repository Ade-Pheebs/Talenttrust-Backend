use soroban_sdk::{Address, BytesN, Env, Vec};

use crate::{
    errors::Error,
    storage::{DataKey, IDEM_KEY_TTL_LEDGERS},
};

/// Maximum number of bets accepted in a single [`place_bets`] call.
///
/// This bound exists so that one invocation always fits inside the Soroban
/// CPU/instruction budget: the contract iterates the whole vector, and an
/// unbounded vector would let a caller construct a batch that can never be
/// applied.  Callers with more than `MAX_BATCH_SIZE` bets must split them
/// into several submissions, each carrying its own idempotency key.
///
/// Raising this constant is a backwards-compatible change; lowering it is
/// not, because it would start rejecting payloads that used to be accepted.
pub const MAX_BATCH_SIZE: u32 = 100;

/// A single bet submitted inside a batch.
///
/// Extend this struct with market-specific fields as the contract grows.
#[soroban_sdk::contracttype]
#[derive(Clone)]
pub struct Bet {
    /// Identifier of the prediction market being bet on.
    ///
    /// Must be non-zero: `0` is reserved for "unassigned" and is rejected
    /// with [`Error::InvalidMarketId`].
    pub market_id: u64,
    /// Amount of the base asset staked, in stroops.
    ///
    /// Must be strictly greater than zero; a non-positive amount is rejected
    /// with [`Error::InvalidBetAmount`].
    pub amount: i128,
}

/// Validate every entry of `bets` against the contract's input boundaries.
///
/// # Rules (evaluated in this order, first failure wins)
///
/// 1. `bets.len() <= MAX_BATCH_SIZE`  – otherwise [`Error::BatchTooLarge`].
/// 2. `bet.market_id != 0`            – otherwise [`Error::InvalidMarketId`].
/// 3. `bet.amount > 0`                – otherwise [`Error::InvalidBetAmount`].
///
/// Rules are applied per entry, scanning from index `0`, so the returned
/// error is deterministic for a given payload.  Duplicate `market_id` values
/// inside one batch are **allowed**: a caller may legitimately place several
/// independent stakes on the same market, and each entry is applied in the
/// order supplied.
///
/// # Invariant: rejected input never consumes the idempotency key
///
/// This function is always called *before* the `(caller, idempotency_key)`
/// sentinel is written, so a payload rejected here leaves the key untouched
/// and the caller can correct the payload and retry with the same token.
/// Any future change that moves validation after the sentinel write would
/// silently burn keys and must be treated as a breaking change.
fn validate_bets(bets: &Vec<Bet>) -> Result<(), Error> {
    if bets.len() > MAX_BATCH_SIZE {
        return Err(Error::BatchTooLarge);
    }

    for bet in bets.iter() {
        if bet.market_id == 0 {
            return Err(Error::InvalidMarketId);
        }
        if bet.amount <= 0 {
            return Err(Error::InvalidBetAmount);
        }
    }

    Ok(())
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
/// * [`Error::BatchTooLarge`] – more than [`MAX_BATCH_SIZE`] entries were
///   supplied.
/// * [`Error::InvalidBetAmount`] – a bet had `amount <= 0`.
/// * [`Error::InvalidMarketId`] – a bet had `market_id == 0`.
/// * [`Error::IdempotentBatchAlreadyApplied`] – the `(caller, idempotency_key)`
///   pair has already been consumed.
///
/// Validation errors are reported before the idempotency key is consumed, so
/// a rejected batch never burns the caller's key.
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

    // Enforce input boundaries before touching any state so that a rejected
    // payload cannot consume the caller's idempotency key.
    validate_bets(&bets)?;

    // ------------------------------------------------------------------
    // Idempotency check
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

// Symbol is used above; import it here to keep the use-site clean.
use soroban_sdk::Symbol;

// ── validation boundary tests ────────────────────────────────────────────────
#[cfg(test)]
mod validation_tests {
    use super::*;
    use crate::PredictifyHybridClient;
    use soroban_sdk::{testutils::Address as _, Address as TestAddress, Env};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn client(env: &Env) -> PredictifyHybridClient<'_> {
        let contract_id = env.register_contract(None, crate::PredictifyHybrid);
        PredictifyHybridClient::new(env, &contract_id)
    }

    fn caller(env: &Env) -> TestAddress {
        TestAddress::generate(env)
    }

    fn key(env: &Env, seed: u8) -> BytesN<32> {
        BytesN::from_array(env, &[seed; 32])
    }

    /// Build a batch from `(market_id, amount)` pairs.
    fn batch(env: &Env, entries: &[(u64, i128)]) -> Vec<Bet> {
        let mut v = Vec::new(env);
        for (market_id, amount) in entries.iter() {
            v.push_back(Bet {
                market_id: *market_id,
                amount: *amount,
            });
        }
        v
    }

    // ── accepted input ───────────────────────────────────────────────────────

    /// The smallest valid bet (market 1, one stroop) is accepted.
    #[test]
    fn minimal_valid_bet_accepted() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);

        env.mock_all_auths();
        contract.place_bets(&user, &batch(&env, &[(1, 1)]), &key(&env, 0x01));
    }

    /// Boundary: `amount` grows and `market_id` is at the top of the u64
    /// range — both extremes are still valid.
    #[test]
    fn upper_bound_values_accepted() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);

        env.mock_all_auths();
        contract.place_bets(
            &user,
            &batch(&env, &[(u64::MAX, i128::MAX)]),
            &key(&env, 0x02),
        );
    }

    /// Boundary: a batch of exactly `MAX_BATCH_SIZE` entries is accepted.
    #[test]
    fn batch_at_max_size_accepted() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);

        let mut v = Vec::new(&env);
        for market_id in 1..=MAX_BATCH_SIZE {
            v.push_back(Bet {
                market_id: u64::from(market_id),
                amount: 7,
            });
        }

        env.mock_all_auths();
        contract.place_bets(&user, &v, &key(&env, 0x03));
    }

    /// Duplicate `market_id` values inside one batch are legitimate and
    /// deterministic: entries are applied in the order supplied.
    #[test]
    fn duplicate_markets_within_batch_accepted() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);

        env.mock_all_auths();
        contract.place_bets(
            &user,
            &batch(&env, &[(42, 10), (42, 20), (42, 30)]),
            &key(&env, 0x04),
        );
    }

    // ── rejected input ───────────────────────────────────────────────────────

    /// `market_id == 0` is reserved and rejected.
    #[test]
    fn zero_market_id_rejected() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);

        env.mock_all_auths();
        let result = contract.try_place_bets(&user, &batch(&env, &[(0, 10)]), &key(&env, 0x05));
        assert_eq!(result, Err(Ok(Error::InvalidMarketId)));
    }

    /// A zero amount is rejected.
    #[test]
    fn zero_amount_rejected() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);

        env.mock_all_auths();
        let result = contract.try_place_bets(&user, &batch(&env, &[(1, 0)]), &key(&env, 0x06));
        assert_eq!(result, Err(Ok(Error::InvalidBetAmount)));
    }

    /// A negative amount is rejected.
    #[test]
    fn negative_amount_rejected() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);

        env.mock_all_auths();
        let result = contract.try_place_bets(&user, &batch(&env, &[(1, -5)]), &key(&env, 0x07));
        assert_eq!(result, Err(Ok(Error::InvalidBetAmount)));
    }

    /// Boundary: `MAX_BATCH_SIZE + 1` entries exceed the accepted window.
    #[test]
    fn batch_over_max_size_rejected() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);

        let mut v = Vec::new(&env);
        for market_id in 1..=MAX_BATCH_SIZE + 1 {
            v.push_back(Bet {
                market_id: u64::from(market_id),
                amount: 7,
            });
        }

        env.mock_all_auths();
        let result = contract.try_place_bets(&user, &v, &key(&env, 0x08));
        assert_eq!(result, Err(Ok(Error::BatchTooLarge)));
    }

    /// When two rules are violated on the same entry the error is stable:
    /// `market_id` is checked before `amount`.
    #[test]
    fn validation_precedence_is_stable() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);

        env.mock_all_auths();
        let result = contract.try_place_bets(&user, &batch(&env, &[(0, -1)]), &key(&env, 0x09));
        assert_eq!(result, Err(Ok(Error::InvalidMarketId)));
    }

    /// An invalid entry anywhere in the batch rejects the whole batch
    /// atomically — no partial application.
    #[test]
    fn one_invalid_entry_rejects_whole_batch() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);

        env.mock_all_auths();
        let result = contract.try_place_bets(
            &user,
            &batch(&env, &[(1, 10), (2, 10), (3, 0), (4, 10)]),
            &key(&env, 0x0a),
        );
        assert_eq!(result, Err(Ok(Error::InvalidBetAmount)));
    }

    // ── retry / failure-mode invariants ──────────────────────────────────────

    /// Regression: a rejected batch must NOT consume the idempotency key, so
    /// the caller can fix the payload and retry with the same token.  Once the
    /// corrected batch succeeds, the key becomes a duplicate.
    #[test]
    fn rejected_batch_does_not_consume_idempotency_key() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);
        let idem = key(&env, 0x0b);

        env.mock_all_auths();

        // 1. Invalid payload → rejected.
        let rejected = contract.try_place_bets(&user, &batch(&env, &[(1, 0)]), &idem);
        assert_eq!(rejected, Err(Ok(Error::InvalidBetAmount)));

        // 2. Same key, corrected payload → accepted (key was never consumed).
        contract.place_bets(&user, &batch(&env, &[(1, 100)]), &idem);

        // 3. The key is now consumed and guards against replays.
        let replay = contract.try_place_bets(&user, &batch(&env, &[(1, 100)]), &idem);
        assert_eq!(replay, Err(Ok(Error::IdempotentBatchAlreadyApplied)));
    }

    /// The empty-batch rejection also happens before the key is consumed.
    #[test]
    fn empty_batch_does_not_consume_idempotency_key() {
        let env = Env::default();
        let contract = client(&env);
        let user = caller(&env);
        let idem = key(&env, 0x0c);

        env.mock_all_auths();

        let empty = contract.try_place_bets(&user, &Vec::new(&env), &idem);
        assert_eq!(empty, Err(Ok(Error::EmptyBatch)));

        contract.place_bets(&user, &batch(&env, &[(9, 1)]), &idem);
    }

    // ── compatibility contract ───────────────────────────────────────────────

    /// The numeric discriminants of every error are part of the on-chain ABI
    /// and must never change.  This test locks them down so an accidental
    /// renumbering fails the build instead of breaking clients.
    #[test]
    fn error_discriminants_are_stable() {
        assert_eq!(Error::IdempotentBatchAlreadyApplied as u32, 1);
        assert_eq!(Error::EmptyBatch as u32, 2);
        assert_eq!(Error::BatchTooLarge as u32, 3);
        assert_eq!(Error::InvalidBetAmount as u32, 4);
        assert_eq!(Error::InvalidMarketId as u32, 5);
    }
}
