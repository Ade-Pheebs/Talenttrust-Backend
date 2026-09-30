use soroban_sdk::{contracttype, Address, BytesN, Env, TryFromVal, Val};

use crate::errors::Error;

/// TTL for consumed idempotency keys, expressed in ledgers.
///
/// At ~5 s/ledger this gives roughly 24 hours of replay protection.
/// After expiry the key is eligible for eviction from instance storage
/// and a fresh submission with the same token is treated as a new batch.
///
/// If you need a longer window, increase this constant and redeploy.
pub const IDEM_KEY_TTL_LEDGERS: u32 = 17_280; // ~24 h at 5 s/ledger

/// Storage keys used by the contract.
///
/// `PlaceBetsIdem(user, key)` stores a sentinel `true` value once a
/// `place_bets` batch has been accepted.  The composite key binds the
/// token to the submitting address so two different callers may reuse the
/// same 32-byte token independently without conflict.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Idempotency sentinel for a `place_bets` call.
    /// Keyed by (caller address, 32-byte token supplied by the caller).
    PlaceBetsIdem(Address, BytesN<32>),
}

/// Validate the existing marker before reserving a token.
///
/// The persisted compatibility contract is an instance-storage boolean `true`
/// under `["PlaceBetsIdem", caller, token]`. Do not change the enum variant name,
/// field order or value encoding without a tested migration. Read as `Val`
/// first so incompatible values produce a stable contract error rather than
/// a conversion panic. Only absence permits a reservation; invalid values are
/// never treated as unused or silently overwritten.
///
/// The authenticated entry point must validate its batch before calling this
/// helper and write the marker in the same transaction as the batch effects.
pub(crate) fn is_idempotency_key_consumed(env: &Env, key: &DataKey) -> Result<bool, Error> {
    match env.storage().instance().get::<_, Val>(key) {
        None => Ok(false),
        Some(value) => match bool::try_from_val(env, &value) {
            Ok(true) => Ok(true),
            // `false` was never written by a valid caller. Fail closed for it
            // and for all unknown layouts; do not disclose the saved value.
            _ => Err(Error::InvalidIdempotencyState),
        },
    }
}
