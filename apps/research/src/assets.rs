//! Brand assets, served as hashed static files (referenced by URL, cached once
//! by the browser) rather than inlined as data URIs.
//!
//! This matters for SSG: a data URI would be re-inlined into EVERY pre-rendered
//! page (the wordmark alone was ~0.46 MB × 3 per page). A hashed URL is a few
//! bytes in the HTML and the file is downloaded once and cached across routes.

use dioxus::prelude::*;

/// The Predator Hunters wordmark (transparent PNG) — nav + footer brand.
pub const PH_LOGO: Asset = asset!("/assets/ph-logo.png");

/// Favicon: the wordmark on a navy tile.
pub const FAVICON: Asset = asset!("/assets/favicon.png");
