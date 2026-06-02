plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
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
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // The Rust core (crates/aegis-client, built as a cdylib by cargo-ndk →
    // libaegis_client.so) is placed under src/main/jniLibs/<abi>/. See README.md.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    buildTypes {
        release {
            isMinifyEnabled = false
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

    // CONVENTIONAL on-device OCR (NOT a vision-LLM) for image/screenshot text;
    // the accessibility tree covers live text. ML Kit runs fully on-device.
    implementation("com.google.mlkit:text-recognition:16.0.1")
}
