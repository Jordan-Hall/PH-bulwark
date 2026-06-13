//! Routed pages. Each is a top-level `#[component]` mounted by `app::Route`.

mod about;
mod approach;
mod contact;
mod home;
mod research;
mod systems;

pub use about::About;
pub use approach::Approach;
pub use contact::Contact;
pub use home::Home;
pub use research::Research;
pub use systems::Systems;
