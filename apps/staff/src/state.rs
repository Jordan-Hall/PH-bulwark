//! Shared console state: the staff session (after a successful StaffLogin).
//! Provided once at the app root and read by the route guard + screens.

use dioxus::prelude::*;

use bulwark_proto::v1::{StaffRole, StaffSession};

#[derive(Clone, Copy)]
pub struct StaffState {
    /// The live staff session, or `None` when signed out. Rehydrated from the
    /// saved token on launch (role/id unknown until the next call refreshes it).
    pub session: Signal<Option<StaffSession>>,
}

impl StaffState {
    pub fn new() -> Self {
        let token = crate::session::staff_token();
        let session = if token.is_empty() {
            None
        } else {
            Some(StaffSession {
                token,
                staff_id: String::new(),
                role: StaffRole::Unspecified as i32,
                issued_ts: 0,
            })
        };
        Self {
            session: Signal::new(session),
        }
    }

    pub fn token(&self) -> String {
        self.session
            .read()
            .as_ref()
            .map(|s| s.token.clone())
            .unwrap_or_default()
    }

    pub fn logged_in(&self) -> bool {
        self.session.read().is_some()
    }

    /// Persist + set a freshly issued session.
    pub fn sign_in(&mut self, session: StaffSession) {
        let _ = crate::session::save_staff_token(&session.token);
        self.session.set(Some(session));
    }

    /// Clear the session token + drop back to the login gate.
    pub fn sign_out(&mut self) {
        let _ = crate::session::clear_staff_token();
        self.session.set(None);
    }
}

/// Human label for a `StaffRole` (content-free; role drives the visible tabs).
pub fn role_label(role: i32) -> &'static str {
    match StaffRole::try_from(role).unwrap_or(StaffRole::Unspecified) {
        StaffRole::Support => "Support",
        StaffRole::SafetyOfficer => "Safety officer",
        StaffRole::Operator => "Operator",
        StaffRole::Admin => "Admin",
        StaffRole::Unspecified => "—",
    }
}
