import java.util.Base64

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ---------------------------------------------------------------------------
// On-device OCR language data (Tesseract `eng.traineddata`).
//
// The conventional-OCR FOSS replacement for the removed ML Kit. The traineddata
// is Apache-2.0 (tesseract-ocr/tessdata_fast). It is BEST-EFFORT fetched into
// generated assets at build time (never committed — the root .gitignore ignores
// the module build dir). If the fetch fails (offline build), the asset is simply
// absent and `Ocr` fails OPEN at runtime — the accessibility view-tree text path
// is unaffected. OCR is an ADDITIVE source for text the tree can't expose, never
// a gate.
// ---------------------------------------------------------------------------
val fetchTessdata = tasks.register("fetchTessdata") {
    description = "Best-effort fetch of Tesseract eng.traineddata (Apache-2.0) into generated assets."
    val outFile = layout.buildDirectory.file("generated/bulwarkAssets/tessdata/eng.traineddata")
    outputs.file(outFile)
    doLast {
        val dest = outFile.get().asFile
        // Already present and plausibly complete (>1 MB) → skip.
        if (dest.exists() && dest.length() > 1_000_000L) return@doLast
        dest.parentFile.mkdirs()
        // Pinned to the 4.1.0 tag for reproducibility (tessdata_fast, Apache-2.0).
        val url = "https://github.com/tesseract-ocr/tessdata_fast/raw/4.1.0/eng.traineddata"
        runCatching {
            uri(url).toURL().openStream().use { input ->
                dest.outputStream().use { output -> input.copyTo(output) }
            }
            logger.lifecycle("fetchTessdata: fetched eng.traineddata (${dest.length()} bytes)")
        }.onFailure { e ->
            // NEVER fail the build for this: OCR fails open without the data.
            logger.warn("fetchTessdata: could not fetch eng.traineddata (${e.message}); on-device OCR will fail open — the accessibility view-tree text path still works.")
            if (dest.exists() && dest.length() < 1_000_000L) dest.delete()
        }
    }
}
// ---------------------------------------------------------------------------
// On-device NSFW model asset (the no-VPN image-safety path).
//
// The SAME license-pinned classifier the engine bundles and the Camera app uses
// (crates/bulwark-vision/models/nsfw_detector.onnx — AdamCodd
// vit-base-nsfw-detector, Apache-2.0, int8 ONNX, 384x384, [-1,1] norm, 2-class
// softmax with index 1 = nsfw) is copied into this module's generated assets at
// build time. NEVER duplicated in git (the root .gitignore ignores the module
// build dir AND *.onnx; the model lives only in the vendored engine copy). It
// lands under the SAME generated-assets root already on the source set below.
// Path check: rootProject.projectDir is platform/android, so ../../crates
// resolves to <repo>/crates. The AccessibilityService scores screen frames with
// it via the Nsfw classifier (co.predatorhunters.bulwark.nsfw). FAIL-OPEN: if
// the model is absent the classifier goes dark and the text paths are unaffected.
// ---------------------------------------------------------------------------
val copyNsfwModel = tasks.register<Copy>("copyNsfwModel") {
    description = "Copy the engine's pinned NSFW ONNX model into generated assets."
    from(rootProject.projectDir.resolve("../../crates/bulwark-vision/models")) {
        include("nsfw_detector.onnx")
    }
    into(layout.buildDirectory.dir("generated/bulwarkAssets/model"))
}

// preBuild is an ancestor of every variant's merge*Assets; matching{} is robust
// to AGP task-registration timing (same pattern as the camera module).
tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(fetchTessdata)
    dependsOn(copyNsfwModel)
}

android {
    namespace = "co.predatorhunters.bulwark"
    compileSdk = 34

    defaultConfig {
        applicationId = "co.predatorhunters.bulwark"
        minSdk = 26          // modern VpnService + foreground-service APIs
        targetSdk = 34
        versionCode = 1
        versionName = "0.0.1"
        ndk {
            // Phones are arm; we ship arm only. The CI emulator smoke test
            // (android-emulator.yml) sets EMULATOR_X86=1 to also include x86_64 so
            // the APK installs on the x86_64 emulator — release/phone builds stay arm.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
            if (System.getenv("EMULATOR_X86") == "1") abiFilters += "x86_64"
        }
    }

    buildFeatures { compose = true }
    // Compose compiler version is now managed by the kotlin.plugin.compose plugin
    // (Kotlin 2.0+); the old composeOptions.kotlinCompilerExtensionVersion is gone.

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // The Rust core (crates/bulwark-client, built as a cdylib by cargo-ndk →
    // libbulwark_client.so) is placed under src/main/jniLibs/<abi>/. See README.md.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    // The build-time-fetched Tesseract eng.traineddata (see fetchTessdata above).
    sourceSets["main"].assets.srcDirs("build/generated/bulwarkAssets")

    // Store the traineddata + ONNX model uncompressed so each streams straight to
    // the app-private file the runtime maps (no inflater pressure on the ~12 MB
    // traineddata or the ~88 MB int8 model whose weights barely compress).
    androidResources {
        noCompress += "traineddata"
        noCompress += "onnx"
    }

    // Release signing is configured ONLY when the keystore is provided via env
    // (CI store-publish job → ANDROID_* secrets). Without it, release stays unsigned
    // and the debug build (used by android.yml) is unaffected — no keystore in repo.
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
    // Provides the Theme.Material3.* XML themes referenced by AndroidManifest.xml
    // (the Compose material3 artifact ships no XML resource themes).
    implementation("com.google.android.material:material:1.12.0")

    // On-screen text is read from the ACCESSIBILITY TREE (live, content-free,
    // fully FOSS) — the primary wired path. For text the tree CANNOT expose
    // (canvas/bitmap-rendered chat, image captions), the AccessibilityService
    // takes a throttled screenshot and runs CONVENTIONAL on-device OCR here —
    // Tesseract (Apache-2.0, fully FOSS, on-device) — feeding the SAME
    // bulwark-text grooming detector. This is the FOSS replacement for the
    // removed ML Kit: a glyph recogniser, never a vision-LLM, never a
    // proprietary SDK. eng.traineddata is fetched by fetchTessdata (above);
    // Ocr fails OPEN if it is absent. See docs/design/on-device-agent.md.
    implementation("cz.adaptech.tesseract4android:tesseract4android:4.9.0")

    // QR scan for the pairing setup code (Apache-2.0 ZXing wrapper). Camera
    // permission is requested at scan time by the embedded capture activity;
    // the decoded text feeds the SAME setup-payload parser as the paste path.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // ONNX Runtime Android (MIT) — runs the bundled Apache-2.0 NSFW classifier
    // fully on-device for the no-VPN image-safety path. The AccessibilityService
    // scores screen frames (and tiles them for localized cover-up) via the Nsfw
    // class; NNAPI accelerator when present, CPU otherwise (Nsfw capability-
    // detects, same as the Camera app's NsfwGate). A vision classifier, never an
    // LLM, never a proprietary SDK. See docs/design/on-device-agent.md.
    // 1.22.0 ships 16 KB-page-aligned native libs (incl. the 4j_jni bridge) (Android 15 requirement).
    implementation("com.microsoft.onnxruntime:onnxruntime-android:1.22.0")
}
