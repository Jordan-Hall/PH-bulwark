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
    }
}

rootProject.name = "Bulwark"
include(":app")
// PH Bulwark Camera — separate child-facing safety-camera APK (single CAMERA
// permission, NO network permission; on-device-only NSFW capture gate). A
// second application module so it shares the wrapper/plugins/CI while leaving
// :app untouched.
include(":camera")
