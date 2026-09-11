//! Application-principal authentication shared by device-facing gRPC services.
//!
//! Transport mTLS protects the connection; this module binds each request to the
//! pairing-minted enrollment credential so a caller cannot choose another
//! `device_id` in its protobuf body.

use crate::accounts::AccountStore;
use tonic::{metadata::MetadataMap, Request, Status};

pub const DEVICE_ID_HEADER: &str = "x-bulwark-device-id";
pub const DEVICE_TOKEN_HEADER: &str = "x-bulwark-device-token";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePrincipal {
    pub device_id: String,
    pub child_id: String,
    pub family_id: String,
}

fn metadata_str<'a>(metadata: &'a MetadataMap, key: &'static str) -> Result<&'a str, Status> {
    metadata
        .get(key)
        .ok_or_else(|| Status::unauthenticated(format!("missing {key}")))?
        .to_str()
        .map_err(|_| Status::unauthenticated(format!("invalid {key}")))
}

/// Strict verification deliberately rejects AccountStore's historical
/// tokenless-enrollment grace. A legacy record accepts every candidate token;
/// probing it with an impossible non-hex sentinel lets production callers detect
/// that state without exposing AccountStore internals. Pair-minted tokens are
/// lowercase hex, so the sentinel can never be a legitimate token.
pub fn verify_device_token_strict(accounts: &AccountStore, device_id: &str, token: &str) -> bool {
    const LEGACY_GRACE_PROBE: &str = "!bulwark-production-requires-pairing!";
    !accounts.verify_device_token(device_id, LEGACY_GRACE_PROBE)
        && accounts.verify_device_token(device_id, token)
}

/// Authenticate an enrolled child device and bind an optional payload identity
/// to that principal. Authentication happens before request bodies are handed to
/// analyzers, storage, fan-out, or other expensive work.
pub fn authenticate_device<T>(
    request: &Request<T>,
    accounts: &AccountStore,
    claimed_device_id: Option<&str>,
) -> Result<DevicePrincipal, Status> {
    let metadata = request.metadata();
    let device_id = metadata_str(metadata, DEVICE_ID_HEADER)?.trim();
    let token = metadata_str(metadata, DEVICE_TOKEN_HEADER)?.trim();
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
        let err = authenticate_device_metadata(&request, &store).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
