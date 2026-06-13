pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        // JitPack hosts Tesseract4Android (cz.adaptech.tesseract4android — the
        // Apache-2.0 conventional-OCR engine the child app uses for screenshot
        // text the accessibility tree can't expose). FOSS source, built by
        // JitPack from the public repo; it is NOT on Maven Central.
        maven { url = uri("https://jitpack.io") }
    }
}

rootProject.name = "Bulwark"
include(":app")
// PH Bulwark Camera — separate child-facing safety-camera APK (single CAMERA
// permission, NO network permission; on-device-only NSFW capture gate). A
// second application module so it shares the wrapper/plugins/CI while leaving
// :app untouched.
include(":camera")
