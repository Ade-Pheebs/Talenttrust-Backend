//! # predictify-hybrid
//!
//! Soroban smart contract for prediction markets.
//!
//! ## Idempotency
//!
//! `place_bets` accepts a caller-supplied `BytesN<32>` idempotency key.
//! The key is stored in instance storage under
//! `DataKey::PlaceBetsIdem(caller, key)` with a TTL of
//! [`storage::IDEM_KEY_TTL_LEDGERS`] ledgers (~24 h).  Repeated
//! submissions with the same `(caller, key)` pair are rejected with
//! `Error::IdempotentBatchAlreadyApplied`.
//!
//! ## Deterministic failure recovery (#1288)
//!
//! * **Atomicity.** `place_bets` validates everything before it writes.
//!   Any failure (error code, failed auth, host/resource error) is rolled
//!   back by Soroban, so a failed call never consumes its key, stores a
//!   receipt or emits an event. There is no partially applied batch.
//! * **Retry after a known failure.** Fix the input if the code says so
//!   and resubmit with the *same* key.
//! * **Retry after an unknown outcome** (timeout, lost response). Call
//!   [`PredictifyHybrid::get_batch_receipt`]:
//!   - `Some(receipt)` → the batch was applied; do not resubmit. Compare
//!     `receipt.batch_hash` with `batch_hash(bets)` to confirm it was yours.
//!   - `None` → nothing was applied under that key; resubmit with the same
//!     key. If the original lands first, the resubmission returns code `1`
//!     instead of applying twice.
//! * **Concurrency.** Transactions touching the same `(caller, key)`
//!   entry are serialised by the ledger; at most one of them applies.
//! * **Upgrade.** Keys consumed by pre-#1288 versions (instance storage)
//!   are still honoured and reported as `legacy` receipts.

#![no_std]

mod bets;
mod errors;
mod storage;

#[cfg(test)]
mod batch_operations_tests;
#[cfg(test)]
mod recovery_tests;

pub use bets::{batch_hash, BatchReceipt, Bet};
pub use errors::Error;
pub use storage::{DataKey, IDEM_KEY_TTL_LEDGERS, INSTANCE_TTL_LEDGERS, MAX_BATCH_SIZE};

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Vec};

#[contract]
pub struct PredictifyHybrid;

#[contractimpl]
impl PredictifyHybrid {
    /// Submit a batch of bets atomically.
    ///
    /// See [`bets::place_bets`] for full documentation.
    pub fn place_bets(
        env: Env,
        caller: Address,
        bets: Vec<Bet>,
        idempotency_key: BytesN<32>,
    ) -> Result<(), Error> {
        bets::place_bets(&env, caller, bets, idempotency_key)
    }

    /// Recovery query (#1288): the receipt of the batch applied under
    /// `(caller, idempotency_key)`, or `None` if nothing was applied (or the
    /// key has expired). Read-only and unauthenticated — receipts hold only
    /// counts, totals and a hash of public bet data.
    pub fn get_batch_receipt(
        env: Env,
        caller: Address,
        idempotency_key: BytesN<32>,
    ) -> Option<BatchReceipt> {
        bets::batch_receipt(&env, caller, idempotency_key)
    }

    /// The largest batch `place_bets` accepts ([`MAX_BATCH_SIZE`]), so
    /// clients can split batches without hard-coding the limit.
    pub fn max_batch_size(_env: Env) -> u32 {
        MAX_BATCH_SIZE
    }
}
