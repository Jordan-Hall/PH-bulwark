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

impl Default for StaffState {
    fn default() -> Self {
        Self::new()
    }
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
                role: crate::session::staff_role(),
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
        let _ = crate::session::save_staff_role(session.role);
        self.session.set(Some(session));
    }

    pub fn role(&self) -> i32 {
        self.session.read().as_ref().map(|s| s.role).unwrap_or(0)
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

// Tab-visibility gates (the server is the authority — these only hide tabs the
// role can't use; an Unspecified rehydrated role hides the gated tabs until the
// next login refreshes it). Fleet/region read is available to every staff role.
pub fn can_support(role: i32) -> bool {
    matches!(
        StaffRole::try_from(role),
        Ok(StaffRole::Support | StaffRole::Admin)
    )
}

pub fn can_cases(role: i32) -> bool {
    matches!(
        StaffRole::try_from(role),
        Ok(StaffRole::SafetyOfficer | StaffRole::Admin)
    )
}

pub fn can_audit(role: i32) -> bool {
    matches!(StaffRole::try_from(role), Ok(StaffRole::Admin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_tab_gate() {
        assert!(can_support(StaffRole::Support as i32));
        assert!(can_support(StaffRole::Admin as i32));
        assert!(!can_support(StaffRole::SafetyOfficer as i32));
        assert!(!can_support(StaffRole::Operator as i32));
        assert!(!can_support(StaffRole::Unspecified as i32));
    }

    #[test]
    fn cases_tab_gate() {
        assert!(can_cases(StaffRole::SafetyOfficer as i32));
        assert!(can_cases(StaffRole::Admin as i32));
        assert!(!can_cases(StaffRole::Support as i32));
        assert!(!can_cases(StaffRole::Operator as i32));
        assert!(!can_cases(StaffRole::Unspecified as i32));
    }

    #[test]
    fn audit_tab_is_admin_only() {
        assert!(can_audit(StaffRole::Admin as i32));
        assert!(!can_audit(StaffRole::Support as i32));
        assert!(!can_audit(StaffRole::SafetyOfficer as i32));
        assert!(!can_audit(StaffRole::Operator as i32));
        assert!(!can_audit(StaffRole::Unspecified as i32));
    }
}
