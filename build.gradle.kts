plugins {
    kotlin("jvm") version "1.3.41"
    `maven-publish`
}

group = "com.mrburny"
version = "0.1-alpha"

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

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = "oqs-provider"
            from(components["kotlin"])
            versionMapping {
                usage("java-api") {
                    fromResolutionOf("runtimeClasspath")
                }
                usage("java-runtime") {
                    fromResolutionResult()
                }
            }
            pom {
                name.set("OQS provider")
                description.set("Provider of OQS implementations of PQ algorithms")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("mrBurny")
                        name.set("Viktor Sergeev")
                        email.set("mrburny.sv@gmail.com")
                    }
                    developer {
                        id.set("MaChengxin")
                        name.set("Chengxin Ma")
                        email.set("cxma@pm.me")
                    }
                }
            }
        }
    }
    repositories {
        mavenLocal()
    }
}
