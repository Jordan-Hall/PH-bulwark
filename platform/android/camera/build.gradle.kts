// PH Bulwark Camera — a SEPARATE child-facing safety-camera APK.
//
// Second application module so it shares the Gradle wrapper, plugin versions
// (declared apply-false in the root build.gradle.kts) and CI with :app while
// leaving :app's build completely untouched. The defining property of this app:
// its manifest declares NO network permission — captures are checked by an
// on-device NSFW model and either saved locally or dropped from memory.
// Nothing can leave the device.
import java.util.Base64

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ---------------------------------------------------------------------------
// On-device NSFW model asset.
//
// The SAME license-pinned classifier the engine bundles
// (crates/bulwark-vision/models/nsfw_detector.onnx — AdamCodd
// vit-base-nsfw-detector, Apache-2.0, int8 ONNX, 384x384, [-1,1] norm,
// 2-class softmax with index 1 = nsfw) is copied into this module's generated
// assets at build time. NEVER duplicated in git (the root .gitignore ignores
// the module build dir; the model lives only in the vendored engine copy).
// Path check: rootProject.projectDir is platform/android, so ../../crates
// resolves to <repo>/crates.
// ---------------------------------------------------------------------------
val copyNsfwModel = tasks.register<Copy>("copyNsfwModel") {
    description = "Copy the engine's pinned NSFW ONNX model into generated assets."
    from(rootProject.projectDir.resolve("../../crates/bulwark-vision/models")) {
        include("nsfw_detector.onnx")
    }
    into(layout.buildDirectory.dir("generated/bulwarkAssets/model"))
}
// preBuild is an ancestor of every variant task (incl. merge*Assets), and
// matching{} stays robust against AGP task-registration timing.
tasks.matching { it.name == "preBuild" }.configureEach { dependsOn(copyNsfwModel) }

android {
    namespace = "co.predatorhunters.bulwark.camera"
    compileSdk = 34

    defaultConfig {
        applicationId = "co.predatorhunters.bulwark.camera"
        // 29 (not :app's 26): scoped storage means MediaStore writes need no
        // storage permission, keeping the manifest at EXACTLY one permission
        // (CAMERA) — the strongest provable "local-only" posture.
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "0.0.1"
        // No abiFilters: this module has no jniLibs of its own; the ONNX
        // Runtime AAR ships per-ABI natives (incl. x86_64 for the CI emulator).
    }

    buildFeatures { compose = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // The build-time-copied model (see copyNsfwModel above).
    sourceSets["main"].assets.srcDirs("build/generated/bulwarkAssets")

    // Store the model uncompressed: int8 weights barely compress, and a stored
    // entry streams straight to the app-private file ORT maps natively
    // (no inflater pressure on an 88 MB asset).
    androidResources { noCompress += "onnx" }

    // Release signing is configured ONLY when the keystore is provided via env
    // (the FOSS release CI — android-release.yml — sets the ANDROID_* secrets).
    // Without it the release stays UNSIGNED and the debug build is unaffected;
    // no keystore ever lives in the repo. This is the SAME env-driven block as
    // :app so the camera APK can ship signed through the self-hosted FOSS path
    // (see docs/distribution.md).
    signingConfigs {
        create("release") {
            val b64 = System.getenv("ANDROID_KEYSTORE_BASE64")
            if (!b64.isNullOrBlank()) {
                val ks = File.createTempFile("release", ".keystore")
                ks.writeBytes(Base64.getDecoder().decode(b64))
                storeFile = ks
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (!System.getenv("ANDROID_KEYSTORE_BASE64").isNullOrBlank()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    // Theme.Material3.* XML themes referenced by AndroidManifest.xml (same as :app).
    implementation("com.google.android.material:material:1.12.0")

    // CameraX (Apache-2.0) — preview + in-memory photo capture + live analysis.
    implementation("androidx.camera:camera-core:1.3.4")
    implementation("androidx.camera:camera-camera2:1.3.4")
    implementation("androidx.camera:camera-lifecycle:1.3.4")
    implementation("androidx.camera:camera-view:1.3.4")

    // ONNX Runtime Android (MIT) — runs the bundled NSFW model fully on-device.
    // NNAPI accelerator when present, CPU otherwise (NsfwGate capability-detects).
    // 1.22.0 ships 16 KB-page-aligned native libs (incl. the 4j_jni bridge) (Android 15 requirement).
    implementation("com.microsoft.onnxruntime:onnxruntime-android:1.22.0")
}
