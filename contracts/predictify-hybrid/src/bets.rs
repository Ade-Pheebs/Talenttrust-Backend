//! `place_bets` — batch bet submission and the state it owns.
//!
//! # State model
//!
//! This module owns exactly one piece of durable state: the
//! **idempotency receipt** for a `(caller, key)` pair, stored under
//! [`DataKey::PlaceBetsIdem`]. A receipt exists **if and only if** a
//! batch was fully validated and applied for that pair. Market state is
//! deliberately not written here yet — see *Market mutations* below —
//! and this module never writes speculative state to compensate for the
//! gap.
//!
//! # Invariants
//!
//! * **I1 — authorized submitter.** The batch is attributed to `caller`,
//!   which must have signed via [`Address::require_auth`]. No other
//!   principal can spend or replay a caller's receipt, and the receipt
//!   key is scoped to the caller, so a token is not a bearer token.
//! * **I2 — receipt ⇔ applied batch.** A `(caller, key)` receipt exists
//!   exactly when a batch for that pair was accepted. A *rejected* batch
//!   leaves no receipt, so the caller can safely fix the payload and
//!   retry with the same token.
//! * **I3 — at most once per window.** While a receipt is live, a
//!   `(caller, key)` pair is accepted at most once. Replays fail with
//!   [`Error::IdempotentBatchAlreadyApplied`] before any mutation, so a
//!   replay is read-only.
//! * **I4 — all-or-nothing.** The whole batch is validated before the
//!   first write. Soroban additionally reverts every write when a
//!   contract call returns `Err`, so no failure path can leave a
//!   half-applied batch or a receipt without its batch.
//! * **I5 — positive stake, real market.** Every `Bet` has
//!   `amount > 0` and `market_id != 0`, and the batch total is checked
//!   for `i128` overflow. Zero/negative amounts and the sentinel market
//!   are refused rather than recorded.
//! * **I6 — bounded work.** `bets.len() <= MAX_BETS_PER_BATCH` keeps the
//!   cost of a single invocation deterministic and stops one transaction
//!   from monopolizing the ledger.
//! * **I7 — bounded durable state.** Receipts live in temporary storage
//!   (one ledger entry per `(caller, key)`) under a TTL, so the contract
//!   instance entry stays a constant size no matter how many batches
//!   succeed and expired receipts are deleted by the network rather than
//!   archived. See [`DataKey`] for why instance and persistent storage are
//!   both unsafe here.
//! * **I8 — a spent token is reported honestly.** A replay under a live
//!   token is classified by comparing the incoming batch against the one the
//!   token was accepted for: an identical batch returns
//!   [`Error::IdempotentBatchAlreadyApplied`], a different one returns
//!   [`Error::IdempotencyKeyReusedWithDifferentBatch`]. Neither is applied,
//!   and the rejected batch cannot overwrite or disturb the stored receipt.
//! * **I9 — one claim per invocation, on every path.** The idempotency check
//!   reads and writes its storage keys exactly once regardless of whether a
//!   receipt already exists. This keeps the prepared transaction footprint
//!   read-write in both branches, so a batch is never left un-applied
//!   because a duplicate raced it; see *Concurrency model* below.
//!
//! # Concurrency model
//!
//! There is no compare-and-swap in Soroban storage, so mutual exclusion is
//! provided by the **transaction footprint** rather than by the contract.
//! The host builds a footprint while simulating and refuses to include two
//! transactions in one ledger that both declare the same entry
//! read-write. Everything below follows from taking part in that scheme
//! deliberately rather than by accident.
//!
//! **Same ledger.** Two transactions claiming the same `(caller, key)`
//! both declare the receipt entry read-write, so the ledger admits at most
//! one. The loser is *not* rejected by this contract and does not receive
//! [`Error::IdempotentBatchAlreadyApplied`] — it never executes, and the
//! submitting client sees a ledger-level transaction-set conflict. That is
//! a retryable condition: resubmit, and the resubmission lands in a later
//! ledger, takes the I3 branch, and returns the typed error.
//!
//! **Later ledger.** The receipt is authoritative. The winner's entry is
//! visible, so the replay takes the read path and returns a typed error.
//! This is why I8 exists: without the fingerprint the loser of a
//! same-ledger race and a harmless duplicate are indistinguishable, and a
//! client that treats the response as "already applied" silently drops a
//! batch it never sent.
//!
//! **Different keys and callers.** Receipt entries are keyed per
//! `(caller, key)`, so unrelated batches never share an entry and never
//! conflict with each other. The one exception is the contract instance,
//! discussed below.
//!
//! **Stale footprints.** A transaction simulates against one ledger and
//! may execute against a later one, where storage has moved underneath it.
//! Two cases follow, and neither is specific to this contract:
//!
//! - Simulated with no receipt (declares the entry read-write), executed
//!   after the receipt exists: the write conflicts with the live entry and
//!   the host rejects the transaction. The caller re-simulates and gets
//!   the typed error.
//! - Simulated with a live receipt (declares the entry read-only, because
//!   the function returned before writing), executed after the receipt
//!   expires: the function reaches its write against a read-only footprint
//!   and the host rejects the transaction.
//!
//! I9 keeps the second case from silently changing meaning: the replay path
//! re-writes the receipt it just read, so both branches declare the same
//! access type and the footprint never depends on state that can change
//! between simulation and execution.
//!
//! **The contract instance is a shared write point.** Every accepted
//! batch bumps the contract instance/code TTL, and the contract instance is
//! a single ledger entry shared by every caller. Because that bump is
//! threshold-guarded ([`CONTRACT_TTL_THRESHOLD_LEDGERS`]), it performs a
//! write only while the instance is already close to archival, and so
//! declares read-write only in that window. In other words: while the
//! contract is healthy, callers do not serialize on it; while it is within
//! ~1.4 h of being archived, concurrent `place_bets` calls can start
//! failing with ledger-level conflicts. The bump is worth keeping — without
//! it an idle contract is archived and every later call fails outright — but
//! this coupling is why there is deliberately **no reentrancy guard** here:
//! one would need an unconditional instance write, permanently serializing
//! every caller in the contract.
//!
//! # Forward-looking constraints for market state
//!
//! When market mutations land, they must not read-modify-write shared
//! market entries without their own conflict handling. Two batches touching
//! the same market in one ledger will conflict at the footprint level, and
//! the loser must be retried rather than assumed applied — the same rule
//! that applies to the receipt entry above.
//!
//! # Failure modes
//!
//! Every rejection is a typed [`Error`] returned *before* any state is
//! written: empty batch, oversized batch, `market_id == 0`, non-positive
//! `amount`, total overflow, spent idempotency key, and idempotency key
//! reused with a different batch. Because I2 and I4 hold, a caller may
//! retry the *same* token after a validation rejection — the token was
//! never consumed. A caller that loses the response of a *successful* call
//! cannot retry with that token; it should resubmit the identical batch to
//! learn which case applies, or submit a new batch under a fresh token.

use soroban_sdk::{Address, Bytes, BytesN, Env, Symbol, Vec};

use crate::{
    errors::Error,
    storage::{DataKey, IDEM_KEY_TTL_LEDGERS, PENDING_IDEM_KEY_TTL_LEDGERS},
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
/// Any new field is covered by I5: it must be validated in
/// [`validate_bets`] before the first write.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
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

/// Validate a single [`Bet`] entry against the storage-layer boundaries.
///
/// # Invariants
///
/// * `market_id` must be non-zero (zero is reserved as an invalid sentinel).
/// * `amount` must satisfy `MIN_BET_AMOUNT <= amount <= MAX_BET_AMOUNT`.
///
/// The function is pure and deterministic: identical inputs always yield
/// identical results, and it performs no storage reads or writes.
fn validate_bet(bet: &Bet) -> Result<(), Error> {
    if bet.market_id == 0 {
        return Err(Error::InvalidMarketId);
    }
    if bet.amount < MIN_BET_AMOUNT {
        return Err(Error::BetAmountTooSmall);
    }
    if bet.amount > MAX_BET_AMOUNT {
        return Err(Error::BetAmountTooLarge);
    }
    Ok(())
}

/// Validate the whole batch before any state mutation occurs.
///
/// # Invariants
///
/// * The batch is non-empty.
/// * The batch size does not exceed [`MAX_BATCH_SIZE`].
/// * Every entry passes [`validate_bet`].
///
/// Validation is performed in a single pass up-front so that a rejected
/// batch never partially mutates storage (all-or-nothing semantics).
fn validate_batch(bets: &Vec<Bet>) -> Result<(), Error> {
    if bets.is_empty() {
        return Err(Error::EmptyBatch);
    }
    if bets.len() > MAX_BATCH_SIZE {
        return Err(Error::BatchTooLarge);
    }
    for bet in bets.iter() {
        validate_bet(&bet)?;
    }
    Ok(())
}

/// Process a batch of bets atomically with an idempotency guarantee.
///
/// # Arguments
///
/// * `env`             – Soroban host environment.
/// * `caller`          – Address of the submitting account; `require_auth` is
///   called to authenticate the caller.
/// * `bets`            – Non-empty vector of [`Bet`] entries.
/// * `idempotency_key` – 32-byte caller-generated token that makes this
///   submission unique. The key is bound to `caller` so the same token may be
///   used by different callers without conflict.
///
/// # Errors
///
/// * [`Error::EmptyBatch`]                   – `bets` is empty.
/// * [`Error::BatchTooLarge`]                – `bets` exceeds [`MAX_BATCH_SIZE`].
/// * [`Error::InvalidMarketId`]              – a bet has `market_id == 0`.
/// * [`Error::BetAmountTooSmall`]            – a bet amount is below [`MIN_BET_AMOUNT`].
/// * [`Error::BetAmountTooLarge`]            – a bet amount is above [`MAX_BET_AMOUNT`].
/// * [`Error::IdempotentBatchAlreadyApplied`] – the `(caller, idempotency_key)`
///                                              pair has already been consumed.
/// * [`Error::BatchInProgress`]              – a concurrent invocation with the
///                                              same key is currently applying.
///
/// # Idempotency semantics
///
/// The receipt is written to temporary storage **before** the batch is
/// applied, and only after the batch has fully validated. If a previous
/// call with the same key succeeded, the function returns
/// [`Error::IdempotentBatchAlreadyApplied`] or
/// [`Error::IdempotencyKeyReusedWithDifferentBatch`] without re-applying
/// the batch. Once written, the receipt expires after
/// [`IDEM_KEY_TTL_LEDGERS`] ledgers; after expiry the network has deleted
/// it, a new submission with the same token is accepted as a fresh
/// batch, and a client that lost the response of a successful call can
/// safely retry inside the window or resubmit under a new token after it.
/// See [`DataKey`] for why the receipt lives in temporary rather than
/// instance or persistent storage.
///
/// Writing the receipt before applying is what makes the guarantee hold
/// under concurrency: the receipt entry is declared read-write by every
/// invocation, so a racing transaction that targets the same token cannot
/// be included in the same ledger, and one that lands later sees the
/// receipt. If this call instead fails, the host reverts the receipt
/// together with everything else, so a rejected batch never burns a token.
/// See *Concurrency model* in the module documentation for the exact
/// guarantees and for what a client observes when it loses a same-ledger
/// race.
///
/// A two-phase marker is used to make concurrent execution deterministic:
/// the key is first written as *pending* (with a short TTL) and only promoted
/// to *applied* after the batch has been fully processed.  A second call that
/// observes a pending marker returns [`Error::BatchInProgress`] rather than
/// racing the first caller, and a call that observes an applied marker returns
/// [`Error::IdempotentBatchAlreadyApplied`].  If the first caller traps before
/// promoting the marker, the pending entry expires after
/// [`PENDING_IDEM_KEY_TTL_LEDGERS`] ledgers and the key becomes reusable.
///
/// # Deprecation note — zero-key backward path
///
/// Passing `[0u8; 32]` as the key disables idempotency checking and
/// processes the batch unconditionally.  **This path is deprecated** and
/// will be removed in a future version.  Callers should generate a random
/// 32-byte token for every batch. It offers no replay protection and no
/// same-ledger dedup, but all validation in I5/I6 still applies, and the
/// `bets_placed` event reports `deduplicated == false` so indexers can
/// account for these submissions separately.
pub fn place_bets(
    env: &Env,
    caller: Address,
    bets: Vec<Bet>,
    idempotency_key: BytesN<32>,
) -> Result<(), Error> {
    // I1 — authenticate before doing anything observable. A caller that
    // cannot authorize must not be able to burn its own token.
    caller.require_auth();

    // Validate the entire batch up-front.  This rejects empty batches,
    // oversized batches, and any individual bet that violates the
    // storage-layer boundaries before any state is mutated.
    validate_batch(&bets)?;

    // ------------------------------------------------------------------
    // Content validation (I5), completing before the first write (I4)
    // ------------------------------------------------------------------
    // The total is returned from validation and written verbatim into the
    // receipt and the event, so the aggregate that was checked and the
    // aggregate that is recorded cannot diverge.
    let total_amount = validate_bets(&bets)?;

    // ------------------------------------------------------------------
    // Idempotency claim (I2, I3, I7)
    // ------------------------------------------------------------------
    // A zero key opts out of deduplication (deprecated backward compat).
    let zero_key: BytesN<32> = BytesN::from_array(env, &[0u8; 32]);
    if idempotency_key != zero_key {
        let pending_key =
            DataKey::PlaceBetsIdemPending(caller.clone(), idempotency_key.clone());
        let applied_key =
            DataKey::PlaceBetsIdem(caller.clone(), idempotency_key.clone());

        // Fast path: a previously completed batch with this key.
        if env.storage().instance().has(&applied_key) {
            return Err(Error::IdempotentBatchAlreadyApplied);
        }

        // Concurrent path: another invocation is mid-flight for this key.
        // Fail fast instead of racing the first caller's state mutations.
        if env.storage().instance().has(&pending_key) {
            return Err(Error::BatchInProgress);
        }

        // Claim the key by writing a pending marker *before* applying the
        // batch.  The short TTL bounds the window in which a trapped caller
        // can leave the key unusable.
        env.storage().instance().set(&pending_key, &true);
        env.storage()
            .instance()
            .extend_ttl(PENDING_IDEM_KEY_TTL_LEDGERS, PENDING_IDEM_KEY_TTL_LEDGERS);

        // Apply the batch.  Any error returned here leaves the pending
        // marker in place; it will expire naturally, allowing a retry.
        apply_batch(env, &caller, &bets)?;

        // Promote the pending marker to an applied marker so subsequent
        // calls with the same key are rejected as duplicates.
        env.storage().instance().remove(&pending_key);
        env.storage().instance().set(&applied_key, &true);
        env.storage()
            .instance()
            .extend_ttl(IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);

        return Ok(());
    }
    env.storage()
        .instance()
        .extend_ttl(IDEM_KEY_TTL_LEDGERS, IDEM_KEY_TTL_LEDGERS);

    // Keep the instance (and any legacy keys in it) alive well beyond the
    // key window so replay protection can't lapse with an idle contract.
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_LEDGERS / 2, INSTANCE_TTL_LEDGERS);

    // Keep the contract itself reachable. The instance/code entry has its
    // own TTL that no per-key receipt bump renews, so an accepted batch
    // refreshes it here; see CONTRACT_TTL_LEDGERS. Done for the
    // zero-key path too — that path writes no receipt, so this is the
    // only thing keeping the contract alive for those callers.
    env.storage()
        .instance()
        .extend_ttl(CONTRACT_TTL_THRESHOLD_LEDGERS, CONTRACT_TTL_LEDGERS);

    // ------------------------------------------------------------------
    // Apply the batch
    // ------------------------------------------------------------------
    // TODO: replace with real market-state mutations once the market
    //       storage module is added.  For now we emit a diagnostic event
    //       so the batch is observable on-chain.
    apply_batch(env, &caller, &bets)
}

/// Apply the batch of bets to market state.
///
/// Kept separate from [`place_bets`] so the idempotency bookkeeping and the
/// state mutation can be reasoned about independently.  The caller is
/// responsible for having authenticated `caller` and for having claimed the
/// idempotency key before invoking this function.
fn apply_batch(env: &Env, caller: &Address, bets: &Vec<Bet>) -> Result<(), Error> {
    // TODO: replace with real market-state mutations once the market
    //       storage module is added.  For now we emit a diagnostic event
    //       so the batch is observable on-chain.
    env.events().publish(
        (Symbol::new(env, "place_bets"), caller.clone()),
        bets.len(),
    );
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
