plugins {
    java
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

tasks.jar {
    archiveBaseName.set("attestation-server")

    manifest {
        attributes(
            "Main-Class" to "app.attestation.server.AttestationServer",
            "Class-Path" to configurations.runtimeClasspath.get().joinToString(" ") { it.name }
        )
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.almworks.sqlite4java:sqlite4java:1.0.392")
    runtimeOnly(files("libs/sqlite4java-prebuilt/libsqlite4java-linux-amd64-1.0.392.so"))
    implementation("com.github.ben-manes.caffeine:caffeine:3.3.1")
    implementation("com.google.guava:guava:33.7.2-jre")
    implementation("com.google.zxing:core:3.5.4")
    implementation("com.google.zxing:javase:3.5.4")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("org.eclipse.angus:jakarta.mail:2.0.5")
    implementation("org.eclipse.parsson:jakarta.json:1.1.9")
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.withType<JavaCompile> {
    options.compilerArgs.addAll(listOf("-Xlint", "-Xlint:-serial"))
}

val copyJavaDeps = tasks.register<Copy>("copyJavaDeps") {
    from(configurations.runtimeClasspath)
    into("build/libs")
}

tasks.build {
    dependsOn(copyJavaDeps)
}

val policyTests = sourceSets.create("policyTest")
policyTests.compileClasspath += sourceSets.main.get().output
policyTests.runtimeClasspath += sourceSets.main.get().output
configurations[policyTests.implementationConfigurationName].extendsFrom(configurations.implementation.get())
configurations[policyTests.runtimeOnlyConfigurationName].extendsFrom(configurations.runtimeOnly.get())

val diamaneOSPolicyTest = tasks.register<JavaExec>("diamaneOSPolicyTest") {
    dependsOn(tasks.named(policyTests.classesTaskName))
    classpath = policyTests.runtimeClasspath
    mainClass.set("app.attestation.server.DiamaneOSPolicyTest")
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(25))
    })
}

// Needs the SQLite native library for the host, by default the bundled Linux x86-64 one.
val profile2Test = tasks.register<JavaExec>("profile2Test") {
    dependsOn(tasks.named(policyTests.classesTaskName))
    classpath = policyTests.runtimeClasspath
    mainClass.set("app.attestation.server.Profile2Test")
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(25))
    })
    val dir = layout.buildDirectory.dir("profile2Test").get().asFile
    workingDir = dir
    systemProperty("sqlite4java.library.path", providers.gradleProperty("sqliteLibraryPath")
            .getOrElse(file("libs/sqlite4java-prebuilt").absolutePath))
    doFirst {
        dir.deleteRecursively()
        dir.mkdirs()
    }
}

tasks.check {
    dependsOn(diamaneOSPolicyTest)
    dependsOn(profile2Test)
}
