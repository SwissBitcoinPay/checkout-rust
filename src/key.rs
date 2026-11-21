//! An integration's secret key, as the merchant's app writes it (SPEC.md §8):
//! `sattleme_ck_<team>.<key>.<relays>`, each part in canonical base64url without padding. It stays
//! on the integrator's server: never in a web page, a repository nor a log.

use std::fmt;

use zeroize::Zeroizing;

use crate::encoding::from_base64url;
use crate::error::Error;
use crate::protocol::{INTEGRATION_KEY_PREFIX, KEY_BYTES};
use crate::relays::decode_relay_list;
use crate::secret::Secret;
use crate::text::to_hex;

/// What an integration's secret key holds.
pub(crate) struct IntegrationKey {
    /// Hex: the team's public key (x only), the author of the integration's channel.
    pub(crate) team: String,
    /// The integration's key (32 bytes).
    pub(crate) key: Secret,
    /// Where its channel was published when the key was given (`wss://` addresses).
    pub(crate) relays: Vec<String>,
}

impl fmt::Debug for IntegrationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntegrationKey")
            .field("team", &self.team)
            .field("key", &self.key)
            .field("relays", &self.relays)
            .finish()
    }
}

/// Reads an integration's secret key, in the order of SPEC.md §8. Fails with `invalid_key` for
/// anything else: another prefix (a link holding its parts included), a part too many or
/// missing, a part that is not canonical base64url, a length other than 32 bytes, a team key off
/// the curve, an invalid relay list. The message never holds the key.
pub(crate) fn parse_integration_key(text: &str) -> Result<IntegrationKey, Error> {
    let rest = text
        .strip_prefix(INTEGRATION_KEY_PREFIX)
        .ok_or_else(|| Error::invalid_key("Not a sattle.me integration key"))?;
    let parts: Vec<&str> = rest.split('.').collect();
    let [team, key, relays] = parts.as_slice() else {
        return Err(if parts.len() < 3 {
            Error::invalid_key("Integration key cut short")
        } else {
            Error::invalid_key("Not a sattle.me integration key")
        });
    };
    let damaged = || Error::invalid_key("Damaged integration key");
    let team = from_base64url(team);
    // The key's bytes are overwritten once read, as every secret's.
    let key = from_base64url(key).map(Zeroizing::new);
    let relays = decode_relay_list(relays);
    let (Some(team), Some(key), Some(relays)) = (team, key, relays) else {
        return Err(damaged());
    };
    let team: [u8; KEY_BYTES] = team.try_into().map_err(|_| damaged())?;
    let key: [u8; KEY_BYTES] = key.as_slice().try_into().map_err(|_| damaged())?;
    if !crate::secp::lift_x(&team) {
        return Err(damaged());
    }
    Ok(IntegrationKey { team: to_hex(&team), key: Secret::new(key), relays })
}
