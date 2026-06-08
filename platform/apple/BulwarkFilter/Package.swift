// swift-tools-version:5.9
//
// Package.swift — a SwiftPM view of the Apple shell's building blocks.
//
// IMPORTANT: a shipping Network Extension content filter is an *app extension*
// embedded in a container app, with entitlements and provisioning that SwiftPM
// cannot express. So the real product is an Xcode project (see README.md →
// "Xcode project layout"). This package exists to:
//   1. expose the Rust static library + C header as a `CBulwarkApple` system
//      target so Swift code (and tests) can call the FFI, and
//   2. give the FilterDataProvider.swift source somewhere to be type-checked /
//      unit-tested on a Mac independent of the full app build.
//
// Build the static lib first (see README): the .a and bulwark_apple.h must be on
// the linker/header search paths. In Xcode you add the .a to the NE target's
// "Link Binary With Libraries" and point Header Search Paths at ../bulwark-apple-ffi/include.

import PackageDescription

let package = Package(
    name: "BulwarkFilter",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "BulwarkFilterCore", targets: ["BulwarkFilterCore"]),
    ],
    targets: [
        // The C ABI of the Rust static library, surfaced via a module map.
        // See Sources/CBulwarkApple/module.modulemap, which includes
        // ../../bulwark-apple-ffi/include/bulwark_apple.h.
        .target(
            name: "CBulwarkApple",
            path: "Sources/CBulwarkApple"
        ),
        // A thin Swift layer that can be unit-tested off the FFI. The actual
        // NEFilterDataProvider lives in the Xcode NE target (FilterDataProvider.swift)
        // because it needs the NetworkExtension entitlement; this library target
        // is for type-checking/bridging only.
        .target(
            name: "BulwarkFilterCore",
            dependencies: ["CBulwarkApple"],
            path: "Sources/BulwarkFilterCore"
        ),
        .testTarget(
            name: "BulwarkFilterCoreTests",
            dependencies: ["BulwarkFilterCore"],
            path: "Tests/BulwarkFilterCoreTests"
        ),
    ]
)
