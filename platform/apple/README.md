# Aegis — Apple child shell (Network Extension content filter)

The Apple child shell is a thin **Swift** app extension that hosts the shared
**Rust** content-safety core as a static library. Apple's sanctioned path for a
third-party content filter is a **Network Extension** content-filter data
provider (`NEFilterDataProvider`), so that is exactly what this is: a
`NEFilterDataProvider` subclass that extracts text from flows it is entitled to
see, asks the Rust core for a verdict over a tiny C ABI, and returns
`.allow()` / `.drop()` — posting a **redacted** local notification on a block.

```
platform/apple/
├── README.md                          ← this file
├── aegis-apple-ffi/                   ← Rust crate (detached cargo workspace)
│   ├── Cargo.toml                     ← [lib] crate-type = ["staticlib","rlib"], empty [workspace]
│   ├── cbindgen.toml                  ← regenerate the C header on a Mac
│   ├── include/
│   │   └── aegis_apple.h              ← hand-authored C ABI (matches src/ffi.rs)
│   └── src/
│       ├── lib.rs                     ← AegisEngine: TextAnalyzer + Policy
│       └── ffi.rs                     ← the C ABI (the only `unsafe` code)
└── AegisFilter/                       ← Swift shell
    ├── FilterDataProvider.swift       ← NEFilterDataProvider subclass
    ├── AegisFilter-Bridging-Header.h  ← imports aegis_apple.h
    ├── AegisFilter.entitlements       ← networkextension (content-filter-provider)
    ├── Info.plist                     ← NSExtension content-filter registration
    ├── Package.swift                  ← SwiftPM view (bridge/tests only)
    ├── Sources/
    │   ├── CAegisApple/module.modulemap        ← exposes aegis_apple.h to Swift
    │   └── AegisFilterCore/AegisEngine.swift   ← safe Swift wrapper over the FFI
    └── Tests/AegisFilterCoreTests/AegisEngineTests.swift
```

## What the Rust core gives us

`aegis-apple-ffi` wraps the **real** Aegis analyzers — no inventions:

- `aegis_text::TextAnalyzer` — the deterministic grooming **rule** engine
  (PRIMARY detector) plus adult-text detection. Built with `TextAnalyzer::new()`
  (returns a `Result`); a span is scored with `analyze_span(request_id, &TextSpan, ts) -> Verdict`.
- `aegis_policy::Policy` — turns a `Verdict` into a `PolicyDecision`
  (action + alert + severity) via `Policy::evaluate(&Verdict, &PolicyContext)`.

It does **not** depend on `aegis-store` / `rusqlite` (the extension persists
nothing, and that crate also fails to build on the dev host). It is rules-first,
has no LLM, sends no telemetry, and logs no message content.

## C ABI (see `aegis-apple-ffi/include/aegis_apple.h`)

```c
AegisEngine *aegis_apple_engine_new(void);
void         aegis_apple_engine_free(AegisEngine *ptr);   // NULL = no-op
int          aegis_apple_classify_text(const AegisEngine *engine,
                                       const char *text_utf8, size_t text_len,
                                       const char *thread_utf8, size_t thread_len,
                                       int *out_category);  // out: AegisAppleCategory
```

`aegis_apple_classify_text` returns `0` = allow, `1` = warn, `2` = block, and
writes a category code (mirrors `aegis.v1.Category`) to `out_category` when it is
non-NULL. **Fail-open**: a NULL engine, NULL text, or invalid UTF-8 returns
`0` (allow) and logs nothing sensitive.

## Build the static library (on a Mac)

The Rust crate compiles to a `staticlib` (`.a`) you link into the NE target.
Cross-compile from a Mac with the Xcode toolchain:

```bash
# 1. Add the Apple Rust targets (once).
rustup target add aarch64-apple-ios          # iOS device
rustup target add aarch64-apple-ios-sim      # iOS simulator (Apple Silicon)
rustup target add x86_64-apple-ios           # iOS simulator (Intel)
rustup target add aarch64-apple-darwin       # macOS Apple Silicon
rustup target add x86_64-apple-darwin        # macOS Intel

cd platform/apple/aegis-apple-ffi

# 2. Build release static libs per target.
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
# (and the simulator targets as needed)

# Output: target/<triple>/release/libaegis_apple_ffi.a
```

Optionally fuse the device + simulator/mac slices into a fat archive or an
`.xcframework`:

```bash
# macOS universal (Apple Silicon + Intel):
lipo -create \
  target/aarch64-apple-darwin/release/libaegis_apple_ffi.a \
  target/x86_64-apple-darwin/release/libaegis_apple_ffi.a \
  -output libaegis_apple_ffi-macos.a

# Or an xcframework spanning iOS device + simulator (recommended for Xcode):
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libaegis_apple_ffi.a \
            -headers include \
  -library libaegis_apple_ffi-iossim.a -headers include \
  -output AegisAppleFFI.xcframework
```

### Regenerate the C header (optional)

The header in `include/aegis_apple.h` is hand-authored to match `src/ffi.rs`. To
regenerate from the exports instead:

```bash
cargo install cbindgen
cd platform/apple/aegis-apple-ffi
cbindgen --config cbindgen.toml --crate aegis-apple-ffi --output include/aegis_apple.h
```

If you change the ABI, regenerate (or hand-edit) the header **and** keep the
Swift bridging header / `module.modulemap` in sync.

## Link it into the Network Extension target

This is an Xcode project (a SwiftPM `Package.swift` cannot express an app
extension with entitlements/provisioning). **Xcode project layout:**

1. **Container app** target (`Aegis`) — a minimal SwiftUI/UIKit app that enables
   the filter via `NEFilterManager.shared().saveToPreferences(...)` and shows
   on/off + the child's age band.
2. **Network Extension** target (`AegisFilter`, type *Content Filter*):
   - Add `FilterDataProvider.swift`.
   - **Build Settings → Objective-C Bridging Header** =
     `platform/apple/AegisFilter/AegisFilter-Bridging-Header.h`.
   - **Build Settings → Header Search Paths** +=
     `$(SRCROOT)/../aegis-apple-ffi/include`.
   - **Build Phases → Link Binary With Libraries** += the built
     `libaegis_apple_ffi.a` (or the `.xcframework`).
   - **Other Linker Flags** if linking the raw `.a`:
     `-laegis_apple_ffi` with a matching `-L` library search path. The Rust
     staticlib also needs the system libs it references; Xcode links the Swift/ObjC
     runtime automatically, and the Rust std deps are self-contained in the `.a`.
   - Set the target's code-signing entitlements to
     `AegisFilter.entitlements`.
   - `Info.plist` registers `NSExtensionPointIdentifier =
     com.apple.networkextension.filter-data` and the principal class
     `$(PRODUCT_MODULE_NAME).FilterDataProvider`.

### Run the Swift bridge tests (optional, on a Mac)

`Package.swift` builds a `CAegisApple` module (from the C header) + a thin
`AegisFilterCore` Swift wrapper so the bridge can be unit-tested without the NE
entitlement. You must put the prebuilt static lib on the linker path:

```bash
cd platform/apple/AegisFilter
swift test \
  -Xlinker -L../aegis-apple-ffi/target/aarch64-apple-darwin/release \
  -Xlinker -laegis_apple_ffi
```

## Entitlements & provisioning

- **Capability:** Network Extensions → *Content Filtering*. Enable it on the App
  ID in the Apple Developer portal for **both** the container app and the NE
  bundle id, and regenerate provisioning profiles that include
  `com.apple.developer.networking.networkextension` with the
  `content-filter-provider` value (see `AegisFilter.entitlements`).
- **App Group** (`group.co.uk.predatorhunters.aegis`) lets the container app and the
  extension share config (on/off, age band). Replace the id with your team's.
- **Distribution:** content filters require a provisioning profile and, for the
  App Store, an approved use case (MDM/parental-control). For development, a
  personal team works on a registered device.
- On **macOS** the user must approve the system extension + content filter in
  System Settings; on **iOS/iPadOS** the filter is enabled via the container app
  through `NEFilterManager`.

## Out of scope on Apple — and by Aegis policy

This shell is **FILTER + ALERTS only**. It cannot, and by design will never:

- **read other apps' messages** or private databases,
- **capture or mirror the screen**,
- **track location**, or
- **block its own uninstall** / remotely control or wipe the device.

Those capabilities are forbidden for third-party apps on Apple's platform, and
Aegis does not build device-control/surveillance features on any platform. The
Apple child shell observes only the flows the system routes to its content
filter, classifies text it is entitled to see, and surfaces transparent,
redacted guardian alerts.
```
