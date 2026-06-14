//! Routed pages. Each is a top-level `#[component]` mounted by `app::Route`.

mod about;
mod approach;
mod contact;
mod coverage;
mod download;
mod home;
mod notfound;
mod ph_bulwark;
mod ph_camera;
mod privacy;
mod research;
mod security;
mod systems;
mod waitlist;

pub use about::About;
pub use approach::Approach;
pub use contact::Contact;
pub use coverage::Coverage;
pub use download::Download;
pub use home::Home;
pub use notfound::NotFound;
pub use ph_bulwark::PhBulwark;
pub use ph_camera::PhCamera;
pub use privacy::Privacy;
pub use research::Research;
pub use security::Security;
pub use systems::Systems;
pub use waitlist::Waitlist;
