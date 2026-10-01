//! Integration tests for `place_bets` idempotency semantics.
//!
//! Run with:
//! ```text
//! cargo test -p predictify-hybrid batch_operations_tests -- --nocapture
//! ```
//!
//! # Compatibility contract
//!
//! Everything asserted in this module is part of the contract's public
//! behaviour. Changing any of it is a breaking change for on-chain clients:
//!
//! * `(caller, idempotency_key)` is the unit of deduplication. Two different
//!   callers may reuse the exact same 32-byte token without conflict, and one
//!   caller may use any number of distinct tokens.
//! * The payload does not participate in the key: reusing a consumed token
//!   with a *different* batch is still rejected.
//! * An empty batch is rejected before any state is touched.
//! * The `[0u8; 32]` token opts out of deduplication entirely and must not
//!   write any state (deprecated backward-compat path).
//! * A consumed token is rejected for `IDEM_KEY_TTL_LEDGERS` ledgers starting
//!   at the ledger it was consumed on, and is accepted again on the first
//!   ledger after that window. The contract instance itself stays invokable
//!   across the whole window.
//! * A sentinel written by an older contract version (no recorded ledger) is
//!   a durable replay guard, never an expiring one.

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, Vec,
};

use crate::{
    bets::Bet, errors::Error, storage::DataKey, storage::IDEM_KEY_TTL_LEDGERS,
    PredictifyHybridClient,
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn fresh_env() -> Env {
    Env::default()
}

fn register(env: &Env) -> (Address, PredictifyHybridClient<'_>) {
    let contract_id = env.register_contract(None, crate::PredictifyHybrid);
    let client = PredictifyHybridClient::new(env, &contract_id);
    (contract_id, client)
}

fn caller(env: &Env) -> Address {
    Address::generate(env)
}

fn key(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

fn zero_key(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn one_bet(env: &Env) -> Vec<Bet> {
    let mut v = Vec::new(env);
    v.push_back(Bet {
        market_id: 1,
        amount: 100,
    });
    v
}

/// Advance the ledger to an absolute sequence number.
fn set_ledger(env: &Env, sequence_number: u32) {
    env.ledger().with_mut(|li| {
        li.sequence_number = sequence_number;
    });
}

/// Read the raw idempotency sentinel for `(caller, token)` as stored on-chain.
fn sentinel_present(env: &Env, contract_id: &Address, user: &Address, token: &BytesN<32>) -> bool {
    env.as_contract(contract_id, || {
        env.storage()
            .instance()
            .has(&DataKey::PlaceBetsIdem(user.clone(), token.clone()))
    })
}

// ── accepted input ───────────────────────────────────────────────────────────

/// A fresh (never-seen) key is accepted and the call succeeds.
#[test]
fn fresh_key_succeeds() {
    let env = fresh_env();
    let (_id, client) = register(&env);
    let user = caller(&env);
    let idem = key(&env, 0x01);

    env.mock_all_auths();
    client.place_bets(&user, &one_bet(&env), &idem);
    // no panic → accepted
}

/// Reusing the same key for the same caller is rejected.
#[test]
fn same_key_rejected_on_second_call() {
    let env = fresh_env();
    let (_id, client) = register(&env);
    let user = caller(&env);
    let idem = key(&env, 0x02);

    env.mock_all_auths();
    // First call must succeed.
    client.place_bets(&user, &one_bet(&env), &idem);

    // Second call with identical key must fail.
    let result = client.try_place_bets(&user, &one_bet(&env), &idem);
    assert_eq!(
        result,
        Err(Ok(Error::IdempotentBatchAlreadyApplied)),
        "expected IdempotentBatchAlreadyApplied on duplicate key"
    );
}

/// Two different callers may each use the same 32-byte token without
/// conflict because the storage key is `(caller, token)`.
#[test]
fn same_token_different_callers_both_accepted() {
    let env = fresh_env();
    let (_id, client) = register(&env);
    let user_a = caller(&env);
    let user_b = caller(&env);
    let shared_idem = key(&env, 0x03);

    env.mock_all_auths();
    client.place_bets(&user_a, &one_bet(&env), &shared_idem);
    client.place_bets(&user_b, &one_bet(&env), &shared_idem);
    // both must succeed
}

/// The same caller using two *different* keys for different payloads is
/// fine — each token is independent.
#[test]
fn same_caller_different_keys_both_accepted() {
    let env = fresh_env();
    let (_id, client) = register(&env);
    let user = caller(&env);

    env.mock_all_auths();
    client.place_bets(&user, &one_bet(&env), &key(&env, 0x04));
    client.place_bets(&user, &one_bet(&env), &key(&env, 0x05));
    // both must succeed
}

// ── replay window ────────────────────────────────────────────────────────────

/// The token is still rejected on the last ledger *inside* the window.
///
/// Boundary: consumed at ledger `c`, the window covers
/// `[c, c + IDEM_KEY_TTL_LEDGERS)`, so `c + IDEM_KEY_TTL_LEDGERS - 1`
/// must still be a duplicate.
#[test]
fn same_key_rejected_on_last_ledger_of_window() {
    let env = fresh_env();
    let (_id, client) = register(&env);
    let user = caller(&env);
    let idem = key(&env, 0x06);

    env.mock_all_auths();

    // Consumed at ledger 0.
    client.place_bets(&user, &one_bet(&env), &idem);

    set_ledger(&env, IDEM_KEY_TTL_LEDGERS - 1);

    let result = client.try_place_bets(&user, &one_bet(&env), &idem);
    assert_eq!(
        result,
        Err(Ok(Error::IdempotentBatchAlreadyApplied)),
        "the token must remain a duplicate on the last ledger inside the window"
    );
}

/// Regression: on the first ledger after the window the token is accepted
/// again, and advancing that far must not archive the contract instance.
///
/// The previous version of this test advanced `IDEM_KEY_TTL_LEDGERS + 1`
/// ledgers, which archived the contract *instance* (instance storage shares
/// the contract's TTL entry) and made the host abort with
/// `Error(Storage, InternalError)` before the contract was ever entered.
/// The instance TTL is now `INSTANCE_TTL_LEDGERS` (2× the replay window), so
/// the same ledger bump reaches contract code and the key expires there.
#[test]
fn same_key_accepted_on_first_ledger_after_window() {
    let env = fresh_env();
    let (contract_id, client) = register(&env);
    let user = caller(&env);
    let idem = key(&env, 0x07);

    env.mock_all_auths();

    // First submission — consumed at ledger 0.
    client.place_bets(&user, &one_bet(&env), &idem);
    assert!(sentinel_present(&env, &contract_id, &user, &idem));

    // First ledger at which the window has elapsed.
    set_ledger(&env, IDEM_KEY_TTL_LEDGERS);

    // Reached contract code (the instance was not archived) and accepted.
    client.place_bets(&user, &one_bet(&env), &idem);
}

/// Once an expired token is accepted again it is re-consumed on that new
/// ledger, so it immediately guards against replays a second time.
#[test]
fn expired_key_is_reconsumed_after_reuse() {
    let env = fresh_env();
    let (_id, client) = register(&env);
    let user = caller(&env);
    let idem = key(&env, 0x08);

    env.mock_all_auths();
    client.place_bets(&user, &one_bet(&env), &idem);

    // Window elapsed → accepted and re-consumed at `IDEM_KEY_TTL_LEDGERS`.
    set_ledger(&env, IDEM_KEY_TTL_LEDGERS);
    client.place_bets(&user, &one_bet(&env), &idem);

    // Same ledger as the re-consumption → duplicate again.
    let replay = client.try_place_bets(&user, &one_bet(&env), &idem);
    assert_eq!(replay, Err(Ok(Error::IdempotentBatchAlreadyApplied)));
}

/// Expiry is scoped to the consuming caller: one caller's elapsed window
/// must not affect another caller's still-active token.
#[test]
fn window_expiry_is_scoped_per_caller() {
    let env = fresh_env();
    let (_id, client) = register(&env);
    let user_a = caller(&env);
    let user_b = caller(&env);
    let shared_idem = key(&env, 0x09);

    env.mock_all_auths();

    client.place_bets(&user_a, &one_bet(&env), &shared_idem);
    client.place_bets(&user_b, &one_bet(&env), &shared_idem);

    // Advance past the window for both, then both are reusable.
    set_ledger(&env, IDEM_KEY_TTL_LEDGERS);
    client.place_bets(&user_a, &one_bet(&env), &shared_idem);
    client.place_bets(&user_b, &one_bet(&env), &shared_idem);
}

/// Same key but different payload (different bets vector): the payload
/// difference is irrelevant — the key alone governs idempotency, so the
/// second call is still rejected.
#[test]
fn same_key_different_payload_rejected() {
    let env = fresh_env();
    let (_id, client) = register(&env);
    let user = caller(&env);
    let idem = key(&env, 0x0a);

    // Two distinct bet vectors.
    let mut bets_b = Vec::new(&env);
    bets_b.push_back(Bet {
        market_id: 2,
        amount: 999,
    });

    env.mock_all_auths();
    client.place_bets(&user, &one_bet(&env), &idem);

    let result = client.try_place_bets(&user, &bets_b, &idem);
    assert_eq!(
        result,
        Err(Ok(Error::IdempotentBatchAlreadyApplied)),
        "duplicate key with different payload must still be rejected"
    );
}

// ── rejected input ───────────────────────────────────────────────────────────

/// An empty bets vector is rejected regardless of the idempotency key.
#[test]
fn empty_batch_rejected() {
    let env = fresh_env();
    let (_id, client) = register(&env);
    let user = caller(&env);

    env.mock_all_auths();
    let result = client.try_place_bets(&user, &Vec::new(&env), &key(&env, 0x0b));
    assert_eq!(
        result,
        Err(Ok(Error::EmptyBatch)),
        "empty batch must return EmptyBatch error"
    );
}

// ── deprecated zero-key path ─────────────────────────────────────────────────

/// The zero key (`[0u8; 32]`) disables idempotency checking; repeated
/// calls with the zero key all succeed (deprecated backward-compat path).
#[test]
fn zero_key_disables_idempotency_deprecated() {
    let env = fresh_env();
    let (_id, client) = register(&env);
    let user = caller(&env);
    let zero = zero_key(&env);

    env.mock_all_auths();
    client.place_bets(&user, &one_bet(&env), &zero);
    // Second call with zero key must also succeed (no dedup check).
    client.place_bets(&user, &one_bet(&env), &zero);
}

/// The zero-key path is a strict opt-out: it must not write a sentinel,
/// otherwise the deprecated path would start consuming storage (and would
/// silently start deduplicating in a later release).
#[test]
fn zero_key_writes_no_sentinel() {
    let env = fresh_env();
    let (contract_id, client) = register(&env);
    let user = caller(&env);
    let zero = zero_key(&env);

    env.mock_all_auths();
    client.place_bets(&user, &one_bet(&env), &zero);
    client.place_bets(&user, &one_bet(&env), &zero);

    assert!(
        !sentinel_present(&env, &contract_id, &user, &zero),
        "the zero key must never be recorded as consumed"
    );
}

// ── upgrade compatibility ────────────────────────────────────────────────────

/// A sentinel written by an older contract version (which stored only the
/// `true` marker, with no recorded ledger) must stay a durable replay
/// guard. If it were treated as "expired", an upgrade would silently make
/// every previously consumed token replayable.
#[test]
fn legacy_sentinel_without_ledger_is_durable() {
    let env = fresh_env();
    let (contract_id, client) = register(&env);
    let user = caller(&env);
    let idem = key(&env, 0x0c);

    env.mock_all_auths();

    // Extend the instance TTL the normal way — via a real submission with
    // a different token — so the instance survives the ledger bump below.
    client.place_bets(&user, &one_bet(&env), &key(&env, 0x0d));

    // Simulate a pre-upgrade write: sentinel only, no ledger entry.
    env.as_contract(&contract_id, || {
        env.storage()
            .instance()
            .set(&DataKey::PlaceBetsIdem(user.clone(), idem.clone()), &true);
    });

    // Still a duplicate on the consuming ledger.
    let immediate = client.try_place_bets(&user, &one_bet(&env), &idem);
    assert_eq!(immediate, Err(Ok(Error::IdempotentBatchAlreadyApplied)));

    // ...and still a duplicate once any replay window would have elapsed,
    // because no consumption ledger is known for it.
    set_ledger(&env, IDEM_KEY_TTL_LEDGERS);
    let later = client.try_place_bets(&user, &one_bet(&env), &idem);
    assert_eq!(
        later,
        Err(Ok(Error::IdempotentBatchAlreadyApplied)),
        "a legacy sentinel must never become replayable after an upgrade"
    );
}
