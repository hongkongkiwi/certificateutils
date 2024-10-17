plugins {
  id("maven-publish")
  alias(libs.plugins.android.library)
  alias(libs.plugins.kotlin.android)
  alias(libs.plugins.dokka)
}

android {
  namespace = "com.github.hongkongkiwi"
  compileSdk = 34

  defaultConfig {
    minSdk = 30

    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
  }

  buildTypes {
    release {
      isMinifyEnabled = false
      proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
    }
  }
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }
  kotlinOptions {
    jvmTarget = "17"
  }
}

dependencies {
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.appcompat)
  implementation(libs.androidx.security.crypto)
  implementation(libs.androidx.annotation)
  implementation(libs.material)
  implementation(libs.bouncycastle.provider)
  implementation(libs.bouncycastle.core)
  implementation(libs.kotlinx.serialization.core)
  implementation(libs.kotlinx.serialization.json)
  testImplementation(libs.junit)
  androidTestImplementation(libs.androidx.junit)
  androidTestImplementation(libs.androidx.espresso.core)
}

tasks.dokkaGfm {
  outputDirectory.set(layout.buildDirectory.dir("dokka-markdown"))
  dokkaSourceSets {
    configureEach {
      sourceRoots.from(file("src/main/kotlin"))
      // Additional configuration, if necessary
    }
  }
}

// Maven publishing configuration for JitPack
afterEvaluate {
  publishing {
    publications {
      create<MavenPublication>("release") {
        from(components["release"])  // Publish the Android component (AAR)
        groupId = "com.github.hongkongkiwi"
        artifactId = "certificateutils"
        version = "1.0.7"
      }
    }
  }
}
