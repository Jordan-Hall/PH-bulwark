//! Application-principal authentication for device-facing gRPC services.
//!
//! Server TLS protects the public connection. Pairing-minted device credentials
//! bind each request to an enrolled installation so callers cannot substitute a
//! different `device_id` in the protobuf body. Deployments may additionally use
//! mTLS, but application authorization does not depend on a client certificate.

use crate::accounts::AccountStore;
use tonic::{metadata::MetadataMap, Request, Status};

/// gRPC metadata key carrying the enrolled device id.
pub const DEVICE_ID_HEADER: &str = "x-bulwark-device-id";
/// gRPC metadata key carrying the pairing-minted device credential.
pub const DEVICE_TOKEN_HEADER: &str = "x-bulwark-device-token";

/// Authenticated child-device principal derived from server-side enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePrincipal {
    /// Authenticated supervised-device id.
    pub device_id: String,
    /// Server-resolved child id.
    pub child_id: String,
    /// Server-resolved family id.
    pub family_id: String,
}

fn metadata_str<'a>(metadata: &'a MetadataMap, key: &'static str) -> Result<&'a str, Status> {
    metadata
        .get(key)
        .ok_or_else(|| Status::unauthenticated(format!("missing {key}")))?
        .to_str()
        .map_err(|_| Status::unauthenticated(format!("invalid {key}")))
}

/// Strictly verify a paired device token.
///
/// `AccountStore` still contains a legacy tokenless-enrollment compatibility
/// branch. A legacy row accepts every candidate token, so probing it with an
/// impossible non-hex sentinel lets the hardened public boundary reject that
/// state without broadening the account-store API. Real pair-minted tokens are
/// lowercase hexadecimal and can never equal the sentinel.
pub fn verify_device_token_strict(accounts: &AccountStore, device_id: &str, token: &str) -> bool {
    const LEGACY_GRACE_PROBE: &str = "!bulwark-production-requires-pairing!";
    !accounts.verify_device_token(device_id, LEGACY_GRACE_PROBE)
        && accounts.verify_device_token(device_id, token)
}

/// Authenticate an enrolled child device and optionally bind a body identity to
/// that principal before analysis/storage/fan-out work is allowed.
pub fn authenticate_device<T>(
    request: &Request<T>,
    accounts: &AccountStore,
    claimed_device_id: Option<&str>,
) -> Result<DevicePrincipal, Status> {
    let device_id = metadata_str(request.metadata(), DEVICE_ID_HEADER)?.trim();
    let token = metadata_str(request.metadata(), DEVICE_TOKEN_HEADER)?.trim();
    if device_id.is_empty() || token.is_empty() {
        return Err(Status::unauthenticated("device credentials are required"));
    }
    if let Some(claimed) = claimed_device_id {
        let claimed = claimed.trim();
        if !claimed.is_empty() && claimed != device_id {
            return Err(Status::permission_denied(
                "payload device_id does not match authenticated device",
            ));
        }
    }
    if !verify_device_token_strict(accounts, device_id, token) {
        return Err(Status::unauthenticated(
            "unknown, legacy-unpaired, or invalid device credential",
        ));
    }
    let (child_id, family_id, _) = accounts
        .child_for_device(device_id)
        .ok_or_else(|| Status::unauthenticated("device is not enrolled"))?;
    Ok(DevicePrincipal {
        device_id: device_id.to_string(),
        child_id,
        family_id,
    })
}

/// Authenticate only from request metadata when no body device id exists.
pub fn authenticate_device_metadata<T>(
    request: &Request<T>,
    accounts: &AccountStore,
) -> Result<DevicePrincipal, Status> {
    authenticate_device(request, accounts, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_metadata_is_rejected_before_work() {
        let store = AccountStore::new();
        let request = Request::new(());
        let error = authenticate_device_metadata(&request, &store).unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }
}
