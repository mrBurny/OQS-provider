plugins {
    kotlin("jvm") version "1.5.21"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("org.openquantumsafe:liboqs-java:1.0")
    implementation("org.bouncycastle:bcprov-jdk15on:1.68")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.7.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.7.2")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    testLogging {
        events("PASSED", "SKIPPED", "FAILED", "STANDARD_OUT", "STANDARD_ERROR")
    }
}