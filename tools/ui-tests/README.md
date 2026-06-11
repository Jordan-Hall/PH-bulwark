# PH Bulwark — Midscene UI test harness

AI-driven, **cross-platform** UI smoke tests for the two Dioxus apps:

- `apps/child` — the onboarding "setup journey" (**PH Bulwark Shield**)
- `apps/parent` — the guardian console (**PH Bulwark Manager**)

The tests are written with [Midscene](https://midscenejs.com): each step is a
natural-language instruction (`aiTap`, `aiInput`, `aiAssert`) executed by a
vision-LLM looking at the running UI. No brittle CSS selectors.

## Why web is the primary path

Dioxus renders the **same RSX** to web, desktop and mobile. The fastest
device-free way to validate the shared UI/logic is to run each app's **web**
target (`dx serve --platform web` -> a localhost URL) and drive it with
Midscene's browser automation (Puppeteer). The Android path
(`@midscene/android` over adb) is optional and validates the **real native
shell**, not just the shared RSX.

| Path                     | What it validates                         | When it runs                          |
| ------------------------ | ----------------------------------------- | ------------------------------------- |
| `test:child:web`         | shared RSX + journey logic (child)        | always (primary)                      |
| `test:parent:web`        | shared RSX + nav (parent console)         | after the one-time parent web edit \* |
| `test:child:android`     | real native Android shell + OS dialogs    | only with a device (auto-skipped)     |

\* See **"Parent app: enable the web target"** below.

## Prerequisites

- **Node** >= 18 (developed on Node 25).
- **dioxus-cli (`dx`)** on PATH — `0.8.0-alpha.0` (matches the apps' pin):
  `cargo install dioxus-cli --version 0.8.0-alpha.0 --locked` if you don't have it.
- A **wasm target** for the web build: `rustup target add wasm32-unknown-unknown`.
- A **vision-capable LLM** for Midscene (the tests "see" the UI). Set the env
  vars below.
- For the Android path only: **adb** + a device/emulator, and the child app
  installed (`dx build --platform android --device <id>`).

## Model / env configuration (no keys are hard-coded)

Copy `.env.example` to `.env` and fill it in — the harness auto-loads `.env` via
`dotenv` (`setup.ts`). The documented Midscene "unified" variables
(https://midscenejs.com/android-getting-started.html):

- `MIDSCENE_MODEL_API_KEY` — your provider key (OpenAI or any OpenAI-compatible API).
- `MIDSCENE_MODEL_BASE_URL` — endpoint, e.g. `https://api.openai.com/v1`.
- `MIDSCENE_MODEL_NAME` — a **vision/multimodal** model (required — the tests "see"
  the UI), e.g. `gpt-4o`.
- `MIDSCENE_MODEL_FAMILY` — *(optional)* family hint for non-OpenAI vision models
  (`qwen-vl`, `gemini`, `ui-tars`). See https://midscenejs.com/model-provider.html.

The legacy `OPENAI_API_KEY` / `OPENAI_BASE_URL` vars also work.

Harness-only optional overrides: `MIDSCENE_HEADED=1` (headed browser for
debugging), `CHILD_WEB_PORT` / `PARENT_WEB_PORT`, `BULWARK_REPO_ROOT`,
`ANDROID_SERIAL`, `CHILD_ANDROID_PACKAGE`.

## Install

```sh
cd tools/ui-tests
npm install
```

This installs both `@midscene/web` (browser path) and `@midscene/android` (device
path) at `1.9.3`, plus `puppeteer` (which downloads a matching Chromium) and
`dotenv`. `@midscene/android` pulls native helpers (`sharp`, `appium-adb`,
`@yume-chan/scrcpy`); on Windows the prebuilt binaries are used automatically.

## Run

From `tools/ui-tests` (each test boots its own `dx serve` on a fixed port and
tears it down afterward — you do **not** need to start a server manually):

```sh
npm run test:child:web      # primary: full child onboarding journey
npm run test:parent:web     # parent console smoke (needs the web edit below)
npm run test:web            # both web suites
npm run test:child:android  # optional; auto-skips with no device
```

Need a server by itself (e.g. to click around manually)? Use the helpers:

```sh
npm run serve:child         # dx serve apps/child  on http://127.0.0.1:8111
npm run serve:parent        # dx serve apps/parent on http://127.0.0.1:8112
```

## Parent app: enable the web target (one-time)

`apps/parent/Cargo.toml` currently pins the renderer to **desktop** and pulls
native deps (`tonic`, `winreg`, `windows`) at the top level, so it does **not**
build to wasm as-is. `test:parent:web` will fail in setup with a clear message
until you make the parent web-buildable. The smallest change mirrors what
`apps/child` already does — add a `web` feature and stop hard-enabling `desktop`:

```toml
[features]
default = ["desktop"]
desktop = ["dioxus/desktop"]
web = ["dioxus/web"]

[dependencies]
# was: dioxus = { version = "0.8.0-alpha.0", features = ["desktop"] }
dioxus = { version = "0.8.0-alpha.0" }   # renderer comes from the feature above
```

The native-only plumbing (gRPC review channel, Windows system-proxy via
`winreg`/`windows`, process spawning) must be `#[cfg(not(target_arch = "wasm32"))]`
-gated (or behind the `desktop` feature) so the web build compiles. That is an
app-side change beyond this harness; the **child** web test needs no such edit
and is the dependable cross-platform signal until then.

## Android path (per the official Midscene Android docs)

Device prep (https://midscenejs.com/android-getting-started.html):
- **USB debugging** ON in Developer options (plus "USB debugging (Security
  settings)" if your OEM has it). Keep the device **unlocked / stay-awake** during
  a run (Developer options → "Stay awake while charging").
- `adb` on PATH (`adb --version`); `ANDROID_HOME` set; confirm the device with
  `adb devices -l` (or `npm run devices`). Wireless: `adb pair <ip:port>` then
  `adb connect <ip:port>` using the code from Wireless debugging.
- Install the native child app first — sideload the built APK:
  `adb install -r platform/android/app/build/outputs/apk/debug/app-debug.apk`.
  Its package id is **`co.predatorhunters.bulwark`** (`CHILD_ANDROID_PACKAGE`).
- Set `ANDROID_SERIAL` (from `adb devices`) to enable the suite; with it unset the
  Android test is skipped. For stubborn text fields set
  `MIDSCENE_ANDROID_IME_STRATEGY=always-yadb`.

On device, the journey's "Grant" buttons trigger real OS dialogs (Accessibility,
VPN consent, device-admin); the test's `aiActionContext` + `aiAct` steps confirm
them.

## Honest scope

- **Web** validates the shared Dioxus **RSX and journey logic** cross-platform,
  with no device — the same components that render on desktop and mobile.
- **Android** validates the **real native shell** (mobile renderer + Android OS
  services). It is the only path that exercises the native permission flows.
- These are **smoke tests**: they confirm the journey is reachable and the key
  brand/state strings appear. They are not pixel-diff or unit tests.
