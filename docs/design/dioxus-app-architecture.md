# Dioxus app architecture — code-split, shared UI kit, refactor plan

Status: design (2026-06-10). Targets `apps/parent` (PH Bulwark Manager) and
`apps/child` (PH Bulwark Shield). Both are pinned to **Dioxus `0.8.0-alpha.0`**
and are **detached cargo workspaces** (`[workspace]` with no members in each
`Cargo.toml`) so the engine's `cargo build --workspace` never pulls the Dioxus
tree. This doc keeps those two constraints.

## 1. Goals and non-goals

Goal: break two single-file apps into cohesive modules so screens, reusable RSX,
state, async gRPC, and the visual theme each live in one obvious place — without
changing behaviour and while keeping the app compiling at every step.

**Use the full Dioxus stack idiomatically (owner directive).** Adopt
`dioxus-router` for ALL navigation (a typed `Route` enum, `Router`/`Outlet`/`Link`,
nested layouts, deep-linkable URLs) rather than hand-rolled enum-dispatch; use
Dioxus **signals + `dioxus-stores`** for shared state, `use_coroutine`/`spawn` for
async, `use_resource` for data the UI awaits, `dioxus-i18n`-ready string seams, and
`asset!`/`manganis` for bundled assets. The two apps already pull `dioxus` with
default features; we lean into them rather than reinventing.

Non-goals: no renderer change (webview stays until the Blitz/native blocker in
`apps/child/Cargo.toml` clears), no proto/contract change, no new business logic.
The CSAM "never preview" rule and the server-isolation model are preserved
verbatim. (Caveat: the apps pin `dioxus 0.8.0-alpha.0`, so `dioxus-router`/
`dioxus-stores` are on the same alpha line — pin them to the matching version and
treat their APIs as alpha-stable-enough for our screens.)

## 2. Current state (what we are splitting)

> **Status (2026-06-10): both splits SHIPPED as flat modules.** Child:
> `theme`/`state`/`components`/`screens`/`router`/`main` on `dioxus-router`
> (typed `Route`, `Outlet`, `JourneyLayout`). Parent: `app`/`theme`/`state`/
> `servers`/`api`/`config`/`process`/`media`/`components`/`screens`/`tests`
> (behaviour-preserving; 12/12 tests green incl. the loopback FakeReview e2e;
> dead `ServerSettings` wrapper dropped). Phase 0's lib/bin split was skipped —
> flat files inside `src/` instead. **Parent `dioxus-router` adoption also
> shipped (2026-06-10):** typed `Route` enum + `ConsoleLayout` (topbar/status
> grid/tab `Link`s) in `router.rs`, the six tabs as routed screens in
> `screens.rs`, all 16 root signals moved into a shared `Console` context
> (`use_context_provider`) so form state survives tab switches; `ActiveView` +
> `nav_class` deleted; `cargo check` clean + 12/12 tests green. The sections
> below describe the pre-split files for reference.

### `apps/child/src/main.rs` — ~383 lines, one file
A linear onboarding journey driven by a `Step` enum
(`Welcome → How → Permissions → Pair → Done`) with `idx()`/`label()` helpers, a
single `App` component holding five `use_signal`s (`step`, `accessibility`,
`network`, `device_admin`, `code`), one reusable `PermissionRow` component, and a
~150-line `CSS` const. Pure UI — the grant buttons flip local signals; on mobile
they will bridge to the native services via `java_plugin!`.

Tangled concerns: step model + progress math + every screen's RSX + the one
reusable component + the whole stylesheet all in `App`/one file.

### `apps/parent/src/main.rs` — ~2751 lines, one file
Six concerns interleaved:
1. **Config/filesystem layer** (~lines 51–143, 1341–1362, 2085–2103): exe
   discovery (`sibling_exe`/`proxy_exe`/`vpn_exe`), config dirs, model/ffmpeg
   resolution, CA paths, segment store dir.
2. **Server inventory + sessions** (~145–487): `CLOUD_REGIONS`, `SavedServer`,
   `ServerInventoryFile`, token/CA per-endpoint paths, FNV session keys,
   `resolve_endpoint`, `cluster_endpoint`, plus the `#[cfg(test)]` helper
   `server_settings_initial_state`.
3. **gRPC client layer** (~526–643, 1258–1335, 2054–2083): `connect_channel`,
   `accounts_client`, account/login/children/pair-code calls, the review stream,
   `submit_decision`, `fetch_segment_remote`, bearer-metadata helper.
4. **Domain model + mapping** (~489–524, 645–835, 1913–1924): `AppStatus`,
   `ActiveView`, `PairCodeUi`, `Alert` + `Alert::from_event`, `seed`,
   `format_when`, `pair_expiry_text`, `can_show_evidence`/`should_show_*`.
5. **Process + Windows system-proxy plumbing** (~1337–1528):
   `enable/disable_system_proxy`, `refresh_wininet`, `Mode`, `ProxyHandle`,
   `kill_proxy`, `spawn_proxy`/`spawn_vpn`, `filter_command`, `proxy_listening`.
6. **The whole UI**: `App` (top bar + status grid + 6-tab nav + a giant `match
   active()`), `ProtectionPanel`, `ServerSettings`/`ServerSettingsPanel`,
   `AlertCard`, `SegmentPlayer`, `CoverageMatrix`, the media helpers
   (`image_data_uri`, `sniff_image_mime`, `sniff_video_mime`, `base64_encode`),
   a ~100-line `CSS` const, and a ~440-line `#[cfg(test)] mod tests`.

Tangled concerns: the `App` component owns 14 signals and inlines the entire
Setup screen (sign-in form + add-child form + pair-code display, ~lines 945–1145)
plus the Alerts list with its optimistic-update decision handler. Async, disk
I/O, Win32 FFI, and RSX share one namespace.

### Top 3 refactor risks
1. **The `#[cfg(test)] mod tests` block depends on many private items by
   `use super::*`** (`Alert`, `Alert::from_event`, `seed`, `resolve_endpoint`,
   `server_inventory_for_choice`, `normalize_custom_servers`,
   `server_for_choice_from`, `server_session_key`, `pair_expiry_text`,
   `review_request_at`, `request_with_bearer`, `should_show_*`, and the
   `#[cfg(test)]` fns `open_pending_review_stream_from`, `submit_decision_to`,
   `server_settings_initial_state`). Moving these into modules requires the test
   module to import from the new paths, and the `#[cfg(test)]`-only fns must move
   to a `pub(crate)`-visible test seam in their new home. Mitigation: keep the
   test module last, update its `use` lines as items move, run `cargo test` (not
   just `cargo check`) after the state/api extractions.
2. **Windows-only `cfg` plumbing.** `enable_system_proxy`/`disable_system_proxy`
   have `#[cfg(windows)]` real bodies and `#[cfg(not(windows))]` stubs, plus
   `refresh_wininet` and the `winreg`/`windows` deps. Extracting these to a
   `system_proxy` module must move BOTH cfg arms together or the non-Windows
   build breaks. Mitigation: move the whole pair as a unit; `cargo check` on the
   dev platform validates the active arm only — note this in the PR.
3. **`Rc<RefCell<Option<Child>>>` + `use_drop` lifecycle is UI-thread-bound.**
   `ProtectionPanel` relies on single-threaded `Rc` semantics and `use_drop`
   cleanup. When this component moves to its own file it must keep its handlers
   and `use_drop` together; splitting the spawn/kill logic away from the panel
   risks `Send`/thread-safety errors the current layout avoids. Mitigation: move
   `ProtectionPanel` whole; only the pure `process`/`system_proxy` free functions
   leave it.

## 3. Target module structure

Each app moves from a binary-only crate (`src/main.rs`) to a **library + thin
binary**: `src/lib.rs` holds the module tree and re-exports `App`; `src/main.rs`
becomes a 4-line `fn main() { dioxus::launch(bulwark_parent::App) }`. This makes
modules testable, lets `#[cfg(test)]` tests live beside the code they cover, and
keeps `dx serve` / `dx build` working (they build the bin, which calls into the
lib).

### 3.1 `apps/parent` — PH Bulwark Manager

```
apps/parent/
  Cargo.toml                 # add [lib]/[[bin]]; deps unchanged
  src/
    main.rs                  # fn main → dioxus::launch(App)
    lib.rs                   # mod declarations + `pub use app::App;`
    app.rs                   # root App: provides global signals/stores, mounts
                             #   Router::<Route> {}; the review coroutine lives here
    router.rs                # #[derive(Routable)] Route enum + RootLayout
                             #   (top bar + status grid + tab nav + <Outlet/>)
    theme.rs                 # pub const CSS (the dark console stylesheet)
    config/
      mod.rs                 # re-exports paths + media
      paths.rs               # app_config_dir, sibling_exe, proxy_exe, vpn_exe,
                             #   repo_root, ca_pem_path, segments_dir,
                             #   session_dir_for_endpoint, *_path_for_endpoint
      media.rs               # nsfw_model(+_display), ffmpeg_binary(+_display),
                             #   config_value, env_or_config
    servers/
      mod.rs                 # re-exports
      model.rs               # SavedServer, ServerInventoryFile, CLOUD_REGIONS,
                             #   DEFAULT_REGION_ID, builtin_servers
      inventory.rs           # load/save/normalize/upsert/remove custom servers,
                             #   server_inventory(_for_choice),
                             #   server_for_choice_from, is_endpoint_url,
                             #   custom_server_id, server_session_key
      resolve.rs             # saved_choice, save_server_choice, resolve_endpoint,
                             #   cluster_endpoint, selected_server_id,
                             #   active_server_label, server_label,
                             #   server_settings_initial_state (#[cfg(test)])
    session.rs               # guardian_token(+_path/_for_endpoint),
                             #   saved_token_for_endpoint, save/clear token,
                             #   cluster_ca_path_for_endpoint
    api/
      mod.rs                 # re-exports
      channel.rs             # connect_channel(_to), accounts_client,
                             #   request_with_bearer
      accounts.rs            # create_guardian_account, login_guardian,
                             #   load_children, create_pair_code_for_child
      review.rs              # open_pending_review_stream(_on/_from),
                             #   submit_decision(_on/_to), review_request_at,
                             #   fetch_segment_remote
    state/
      mod.rs                 # re-exports
      status.rs              # AppStatus, ActiveView, session_status_text,
                             #   nav_class
      alert.rs               # Alert, Alert::from_event, PairCodeUi, seed,
                             #   format_when, pair_expiry_text,
                             #   can_show_evidence, should_show_thumbnail/snippet
    process/
      mod.rs                 # re-exports
      filter.rs              # Mode, ProxyHandle, kill_proxy, filter_command,
                             #   spawn_proxy, spawn_vpn, proxy_listening,
                             #   ca_present, ca_trust_command
      system_proxy.rs        # #[cfg(windows)] enable/disable + refresh_wininet,
                             #   #[cfg(not(windows))] stubs (BOTH arms together)
    media/
      mod.rs                 # re-exports
      encode.rs              # base64_encode
      sniff.rs               # sniff_image_mime, sniff_video_mime, image_data_uri
      segment.rs             # load_segment_from_disk
    screens/                 # one routed component per Route variant (Routable)
      mod.rs                 # re-exports each screen component
      setup.rs               # SetupScreen: sign-in form + add-child + pair code
                             #   (the inlined ActiveView::Setup arm)
      alerts.rs              # AlertsScreen: empty state + alert list + decide cb
      children.rs            # ChildrenScreen: load + child rows
      protection.rs          # ProtectionPanel (whole, incl. use_drop)
      server.rs              # ServerSettingsPanel + ServerSettings wrapper
      coverage.rs            # CoverageScreen wrapping CoverageMatrix
    components/
      mod.rs                 # re-exports
      alert_card.rs          # AlertCard (CSAM exception lives here)
      segment_player.rs      # SegmentPlayer
      coverage_matrix.rs     # CoverageMatrix
      status_grid.rs         # the 3 status tiles (extracted from App)
      tab_nav.rs             # the 6-tab <nav> as <Link to=Route::…> (router-active class)
  tests/
    servers.rs               # moved pure server-resolution tests
    review_e2e.rs            # the FakeReview gRPC tests (was #[cfg(test)] mod)
```

Notes on the parent split:
- **`screens/` vs `components/`**: a *screen* is mounted by `app.rs` for one
  `ActiveView`; a *component* is reusable RSX a screen mounts. `AlertCard`,
  `SegmentPlayer`, `CoverageMatrix`, `status_grid`, `tab_nav` are components;
  `SetupScreen`/`AlertsScreen`/etc are screens.
- The big inlined Setup arm (sign-in + add-child + pair code, currently ~200
  lines inside `App`) becomes `screens/setup.rs`. Its signals
  (`create_account`, `email`, `password`, `display_name`, `child_name`,
  `pair_code`, `setup_note`/`error`/`busy`) move into `SetupScreen` as local
  `use_signal`s; it calls `api::accounts` and `session` directly and raises an
  `on_status_changed: EventHandler<()>` so `App` can refresh `AppStatus`.
- The review coroutine stays in `app.rs` (it owns the shared `alerts`/`offline`
  signals the top-bar status grid reads). `AlertsScreen` receives `alerts`,
  `offline`, and an `on_decide` handler as props.
- The `#[cfg(test)]`-only network seams (`open_pending_review_stream_from`,
  `submit_decision_to`, `server_settings_initial_state`) become `pub(crate)`
  in their new modules guarded by `#[cfg(test)]`, and the integration tests move
  to `tests/` (crate-external), importing from the new `bulwark_parent::` lib
  paths. The pure-logic tests can alternatively stay as `#[cfg(test)] mod tests`
  inside each module — preferred for unit-level ones (`server_session_key`,
  `normalize_custom_servers`, `review_request_at`, `Alert::from_event`).

### 3.2 `apps/child` — PH Bulwark Shield

The child app is tiny today, but it should adopt the SAME shape so it scales as
the real enrollment flow (server choice + `RedeemPairCode` over the Rust bridge,
mirroring `Onboarding.kt`) lands. The Android `Onboarding.kt` journey has SEVEN
steps (`Welcome, Transparency, Accessibility, Vpn, AntiRemoval, Pair, Done`); the
Dioxus child currently collapses the three permissions into one `Permissions`
screen. The target mirrors the Android step structure so the two child UIs stay
conceptually aligned (one permission per screen, an optional anti-removal step,
a real pair step).

```
apps/child/
  Cargo.toml                 # add [lib]/[[bin]]; deps unchanged
  Dioxus.toml                # unchanged (mobile manifest/permissions)
  src/
    main.rs                  # fn main → dioxus::launch(App)
    lib.rs                   # mod declarations + `pub use app::App;`
    app.rs                   # App: global signals/stores + Router::<Route> {}
    router.rs                # #[derive(Routable)] Route (one variant per step) +
                             #   JourneyLayout (progress shield + <Outlet/>); step
                             #   nav via navigator()/Link, resumes at first-incomplete
    theme.rs                 # pub const CSS (the warm dawn stylesheet)
    state/
      mod.rs
      step.rs                # Step↔Route helpers: idx()/label()/TOTAL,
                             #   ProgressSteps, first_incomplete_step, SetupState
    bridge/
      mod.rs                 # native-grant + enrollment seam
      grants.rs              # grant_accessibility/vpn/anti_removal: java_plugin!
                             #   on mobile (#[cfg(feature="mobile")]), local
                             #   signal flip on desktop preview
      enroll.rs              # redeem_pair_code(endpoint, code, device_id) seam,
                             #   resolve_endpoint, normalized_pair_code (mirror
                             #   the Kotlin helpers); desktop returns a stub Ok
    screens/
      mod.rs
      welcome.rs             # WelcomeStep
      transparency.rs        # TransparencyStep ("What PH Bulwark does")
      accessibility.rs       # AccessibilityStep (was part of Permissions)
      network.rs             # NetworkStep / VPN (was part of Permissions)
      anti_removal.rs        # AntiRemovalStep (optional; new, mirrors Android)
      pair.rs                # PairStep (server choice + code + redeem)
      done.rs                # DoneStep (status pills / summary)
    components/
      mod.rs
      step_scaffold.rs       # StepScaffold: centred content + primary/secondary
      permission_row.rs      # PermissionRow (kept; or fold into PermissionScaffold)
      permission_scaffold.rs # PermissionScaffold: icon+title+why+status+grant
      progress.rs            # the fill-shield progress + "Step n of N" label
      pills.rs               # status pills / promise rows / trust chip
```

Notes on the child split:
- `Step` grows from 5 to 7 variants to mirror Android
  (`Welcome, Transparency, Accessibility, Network, AntiRemoval, Pair, Done`).
  `TOTAL`/`idx()`/`label()` update accordingly; `ProgressSteps` (the four dot
  steps: Accessibility, Network, Pair — Android counts AntiRemoval too) lives in
  `state/step.rs`. This is an intentional UX upgrade, done in a SEPARATE commit
  AFTER the mechanical split so the diff is reviewable.
- The native bridge is isolated in `bridge/` behind `#[cfg(feature = "mobile")]`
  so desktop preview keeps flipping local signals (today's behaviour) and the
  mobile target wires `java_plugin!` without touching screen code.
- `StepScaffold`/`PermissionScaffold` are the Dioxus mirrors of the Kotlin
  composables of the same name — same prop shape (`primaryLabel`, `onPrimary`,
  `secondaryLabel`, `onSecondary`, `granted`, `whyLine`, `trust`).

## 4. Shared UI kit — `bulwark-ui-kit`

**Recommendation: yes, introduce `crates/bulwark-ui-kit` — but stage it.** The
two apps deliberately have *different* visual languages today (parent = dark
console `#10110f`; child = warm cream `#FBF6EE`). A shared kit must therefore be
**theme-parameterised**, not a single hard-coded palette. Do NOT block the
per-app split on the kit; land the kit in Phase 6 once both apps are modular.

### What it exports

```
crates/bulwark-ui-kit/
  Cargo.toml                 # dioxus (no renderer feature — apps pick it),
                             #   detached or its own workspace; MIT/Apache only
  src/
    lib.rs
    theme.rs                 # struct Theme { palette + type scale as CSS vars };
                             #   fn theme_css(&Theme) -> String → :root { --… }.
                             #   Two presets: Theme::console(), Theme::shield().
    primitives.rs            # PrimaryButton, GhostButton, Card, Field (label+input)
    status.rs                # StatusPill, StatusLine (✓/• + on/off label),
                             #   Dot (on/off), Badge (ok/warn/neutral)
    step.rs                  # StepScaffold, ProgressDots / ProgressShield,
                             #   "Step n of N" header
    server_picker.rs         # ServerRow + ServerList (shared by parent Server
                             #   screen and child Pair screen — same CLOUD_REGIONS)
```

Design rule for the kit: **components emit semantic class names** (`pill`,
`primary`, `card`, `status-line`) and the *app* supplies the actual colours via
`theme_css(Theme)` injected once at the root. This keeps RSX shared while letting
parent stay dark and child stay warm. No component hard-codes a hex value.

### How each app depends on it

Path dependency, consistent with the existing `bulwark-proto` path dep in
`apps/parent/Cargo.toml`:

```toml
# apps/parent/Cargo.toml and apps/child/Cargo.toml
bulwark-ui-kit = { path = "../../crates/bulwark-ui-kit" }
```

Detached-workspace caveat: each app is its own `[workspace]`, and so must
`bulwark-ui-kit` be (or live under a workspace that does NOT include the engine),
or it gets pulled into the engine's `cargo build --workspace`. Give
`bulwark-ui-kit` an empty `[workspace]` table too, exactly like the apps, so it
builds standalone and as a path dep without re-attaching the engine tree. The kit
must NOT enable a dioxus renderer feature — the consuming app does (`desktop` for
parent, `desktop`/`mobile`/`web` for child), so the same kit works on all
targets.

Licensing: kit stays MIT/Apache-permissive only (matches the repo's no-GPL rule);
it depends on `dioxus` and nothing heavier.

### Shared model crate (smaller, do first if anything)
The `CLOUD_REGIONS`/`DEFAULT_REGION_ID` list and the `resolve_endpoint` /
`normalized_pair_code` logic are duplicated across `apps/parent` (Rust) and
`Onboarding.kt` (Kotlin) — and will be duplicated again in the Dioxus child. A
tiny `bulwark-app-core` crate (pure Rust, no Dioxus) exporting the region table +
endpoint/pair-code helpers is optional but high-value: both Dioxus apps can share
it, and it documents the contract the Kotlin side must mirror. List it as a
follow-up; not required for the split.

## 5. Maintainability model (conventions)

- **One screen per file.** A file in `screens/` exports exactly one top-level
  screen component named `<Name>Screen` (parent) or `<Name>Step` (child). No
  screen defines another screen.
- **`screens/` = routed/dispatched, `components/` = reusable.** If `app.rs`
  mounts it for a tab/step, it's a screen. If a screen mounts it, it's a
  component. Components take props, own no app-global signals, and never call
  `api::*` directly (they raise `EventHandler`s).
- **Presentation vs business logic.** RSX + local `use_signal` UI state live in
  `screens`/`components`. Pure transforms (`Alert::from_event`, `format_when`,
  `resolve_endpoint`, `normalize_custom_servers`, `sniff_*`, `base64_encode`)
  live in `state`/`servers`/`media` and have unit tests. FS/process/Win32 live in
  `config`/`process`. Network lives in `api`.
- **Async isolation.** Views never `.await`. They `spawn(async move { … })` an
  `api::*` call and write the result back into a signal, exactly as the current
  Setup/Alerts handlers do. All gRPC lives behind `api/` free functions that
  return `anyhow::Result<T>`; the on-disk seams (`*_from`/`*_to`) stay
  `#[cfg(test)]`.
- **Naming.** Modules `snake_case`; components `PascalCase`; the const stylesheet
  is `pub const CSS: &str` per app in `theme.rs`. Free functions keep their
  current names (memory note: don't rename crates/env/paths — same spirit applies
  to public fn names the tests pin, e.g. `resolve_endpoint`, `server_session_key`,
  `review_request_at`).
- **State ownership.** App-global signals (`alerts`, `offline`, `active`,
  `status`) live in `app.rs` and pass DOWN as props. Screen-local signals
  (form fields, busy flags) live in the screen. No global mutable singletons.
- **Routing/navigation — `dioxus-router`, first-class (owner directive).** Every
  screen is a variant of a typed `#[derive(Routable)] enum Route` in `router.rs`.
  The root `App` mounts `Router::<Route> {}`; a `#[layout(RootLayout)]` (parent) /
  `JourneyLayout` (child) renders the persistent chrome (top bar + status grid +
  tab nav, or the progress shield) once and an `<Outlet/>` for the active screen.
  Navigation is `Link { to: Route::Alerts {}, .. }` and `navigator().push(..)` —
  never a manual `match`. This gives back/forward, deep links (`Route::Children`,
  `Route::Pair`), and active-tab styling for free. Add the dep to each
  `Cargo.toml`:
  ```toml
  dioxus = { version = "0.8.0-alpha.0", features = ["router"] }
  # or: dioxus-router = "0.8.0-alpha.0"   (pin to the dioxus version)
  ```
  - **Parent** `Route` (nested under `RootLayout`): `Setup`, `Alerts`, `Children`,
    `Protection`, `Server`, `Coverage` — the six tabs become six routes; the old
    `ActiveView` enum is deleted in favour of `Route`.
  - **Child** `Route` (nested under `JourneyLayout`): `Welcome`, `Transparency`,
    `Accessibility`, `Network`, `AntiRemoval`, `Pair`, `Done` — one route per step;
    "next/back" is `navigator().push(next_route)`, and on launch the app redirects
    to `first_incomplete_step()`'s route so a half-finished setup resumes (and is
    deep-linkable, e.g. for support: "open the Pair step"). Router APIs are on the
    same 0.8-alpha line — pin and treat as alpha (see §1 caveat).
- **Shared state — signals + `dioxus-stores`.** App-global state (`AppStatus`,
  `alerts`, `offline`, `SetupState`) lives in a `dioxus-stores` store or a
  `use_context` of `Signal`s provided at the root, so any routed screen reads it
  without prop-drilling through the router `Outlet`. Screen-local state stays in
  `use_signal`. Data the UI awaits (children list, segment bytes) uses
  `use_resource`; long-lived streams (the review stream) use `use_coroutine`.
- **Module re-exports.** Each folder has a `mod.rs` that `pub use` its public
  items so call sites import `crate::api::open_pending_review_stream`, not
  `crate::api::review::open_pending_review_stream`. This keeps move-churn low.

## 6. Incremental refactor workflow (compiles at every step)

Constraints honoured throughout: Dioxus `0.8.0-alpha.0`, webview renderer (the
`Cargo.toml` comment blocks native/Blitz on this toolchain — do not touch the
renderer), detached `[workspace]` per app, `bulwark-proto` path dep unchanged.
Verify with `cd apps/<app> && cargo check` after each step; run
`cargo test` after any step that touches the parent test module.

### Phase 0 — lib/bin split (both apps)
1. Add to each `Cargo.toml`:
   ```toml
   [lib]
   name = "bulwark_parent"   # or bulwark_child
   path = "src/lib.rs"
   [[bin]]
   name = "bulwark-parent"   # or bulwark-child
   path = "src/main.rs"
   ```
2. Create `src/lib.rs` = the current `main.rs` body MINUS `fn main`, with the
   module tree's first `mod`/`pub use` added incrementally. Reduce `main.rs` to
   `fn main() { dioxus::launch(bulwark_parent::App); }`.
3. `cargo check` + `cargo test`. (Behaviour identical; everything still in
   `lib.rs` for now.)

### Phase 1 — extract `theme.rs` (lowest risk)
4. Move each `const CSS` into `src/theme.rs` as `pub const CSS`. Replace the
   `style { {CSS} }` reference with `theme::CSS`. `cargo check`.

### Phase 2 — extract pure helpers (no Dioxus)
Parent: create `media/` (`base64_encode`, `sniff_*`, `image_data_uri`,
`load_segment_from_disk`), `config/` (paths + media), `servers/` (model +
inventory + resolve), `session.rs`. Child: create `state/step.rs`.
5. Move functions in dependency order (leaves first: `base64_encode`,
   `server_session_key`, `is_endpoint_url`), add `mod`/`pub use` to `lib.rs`,
   fix call sites. `cargo check` + `cargo test` after each module (the test
   module pins many of these — update its imports as they move).

### Phase 3 — extract domain state + api
6. Parent: `state/` (`AppStatus`, `ActiveView`, `Alert`, `PairCodeUi`, `seed`,
   `format_when`, `pair_expiry_text`, `should_show_*`) then `api/`
   (`channel`/`accounts`/`review`). Keep the `#[cfg(test)]` network seams
   `pub(crate)`. `cargo check` + `cargo test`.

### Phase 4 — extract process/system-proxy (parent, Windows-cfg care)
7. Move `process/filter.rs` and `process/system_proxy.rs` as a UNIT — both
   `#[cfg(windows)]` and `#[cfg(not(windows))]` arms together (Risk #2).
   `ProtectionPanel` still references them via `crate::process::*`. `cargo check`.

### Phase 5 — extract components, then screens (both apps)
8. Components first (they have the fewest inbound deps): parent
   `alert_card.rs`, `segment_player.rs`, `coverage_matrix.rs`, `status_grid.rs`,
   `tab_nav.rs`; child `step_scaffold.rs`, `permission_scaffold.rs`,
   `progress.rs`, `permission_row.rs`. `cargo check`.
9. Screens next: parent `setup.rs` (lift the inlined Setup arm; move its 8
   signals into the screen; expose `on_status_changed`), `alerts.rs`,
   `children.rs`, `protection.rs` (move `ProtectionPanel` WHOLE incl. `use_drop`
   — Risk #3), `server.rs`, `coverage.rs`. Child: `welcome/transparency/
   accessibility/network/pair/done`. `cargo check` + `cargo test`.

### Phase 5b — adopt `dioxus-router` (replaces the enum-dispatch)
9a. Add the `router` feature/dep (§5) to each `Cargo.toml`. Define
    `router.rs`: the `#[derive(Routable)] Route` enum + the `RootLayout`
    (parent) / `JourneyLayout` (child) with `<Outlet/>` for the persistent chrome.
9b. Replace `app.rs`'s `match active()` with `Router::<Route> {}`; delete the
    `ActiveView`/`Step`-dispatch glue. Convert the parent tab nav to `Link`s and
    the child step "next/back" to `navigator().push(..)`; redirect launch to
    `first_incomplete_step()`'s route. Move global state into a `dioxus-stores`
    store / root `use_context` so routed screens read it through the `Outlet`.
    `cargo check` + `cargo test` (the e2e/UI behaviour is unchanged; URLs are new).

### Phase 6 — child UX upgrade (separate commit) + shared kit (optional)
10. Child: add `Step::Transparency` and `Step::AntiRemoval`, split the single
    `Permissions` screen into per-permission screens, add a real `PairStep`
    (server picker + `bridge::enroll::redeem_pair_code`) mirroring
    `Onboarding.kt`. Done as its own reviewable commit AFTER the mechanical split.
11. (Optional) Introduce `crates/bulwark-ui-kit` (Section 4): move
    `StepScaffold`/`ProgressDots`/`StatusPill`/`ServerRow`/`Theme` into it, add
    the path dep to both apps, parameterise colour via `theme_css(Theme)`.
    `cargo check` both apps.

### Phase 7 — relocate tests
12. Move the parent `FakeReview` gRPC integration tests to
    `apps/parent/tests/review_e2e.rs` (importing `bulwark_parent::*`); keep
    fast unit tests as `#[cfg(test)] mod tests` inside their modules. `cargo test`.

Each phase is independently shippable and leaves `git diff` reviewable (moves +
import fixes only, no logic change) until Phase 6's intentional UX upgrade.
