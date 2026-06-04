plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "co.libertyware.aegis"
    compileSdk = 34

    defaultConfig {
        applicationId = "co.libertyware.aegis"
        minSdk = 26          // modern VpnService + foreground-service APIs
        targetSdk = 34
        versionCode = 1
        versionName = "0.0.1"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a") }
    }

    buildFeatures { compose = true }
    // Compose compiler version is now managed by the kotlin.plugin.compose plugin
    // (Kotlin 2.0+); the old composeOptions.kotlinCompilerExtensionVersion is gone.

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // The Rust core (crates/aegis-client, built as a cdylib by cargo-ndk →
    // libaegis_client.so) is placed under src/main/jniLibs/<abi>/. See README.md.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    // Release signing is configured ONLY when the keystore is provided via env
    // (CI store-publish job → ANDROID_* secrets). Without it, release stays unsigned
    // and the debug build (used by android.yml) is unaffected — no keystore in repo.
    signingConfigs {
        create("release") {
            val b64 = System.getenv("ANDROID_KEYSTORE_BASE64")
            if (!b64.isNullOrBlank()) {
                val ks = File(project.buildDir, "release.keystore")
                ks.parentFile?.mkdirs()
                ks.writeBytes(java.util.Base64.getDecoder().decode(b64))
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

    // CONVENTIONAL on-device OCR (NOT a vision-LLM) for image/screenshot text;
    // the accessibility tree covers live text. ML Kit runs fully on-device.
    implementation("com.google.mlkit:text-recognition:16.0.1")
}
