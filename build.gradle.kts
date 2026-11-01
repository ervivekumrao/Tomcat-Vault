/*
 * Copyright 2024-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
    java
    jacoco
}

group = "com.github.ervivekumrao"
version = "2.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
        resources {
            setSrcDirs(listOf("src"))
            exclude("**/*.java")
        }
    }
    test {
        java {
            setSrcDirs(listOf("test"))
        }
    }
}

val tomcatVersion = "9.0.123"

dependencies {
    compileOnly("org.apache.tomcat:tomcat-dbcp:$tomcatVersion") {
        exclude(group = "org.apache.tomcat", module = "tomcat-juli")
    }
    compileOnly("org.apache.tomcat:tomcat-jdbc:$tomcatVersion") {
        exclude(group = "org.apache.tomcat", module = "tomcat-juli")
    }
    compileOnly("org.apache.tomcat:tomcat-juli:$tomcatVersion")
    compileOnly("org.apache.tomcat:tomcat-catalina:$tomcatVersion")
    compileOnly("com.zaxxer:HikariCP:4.0.3")
    testImplementation("org.apache.tomcat:tomcat-dbcp:$tomcatVersion") {
        exclude(group = "org.apache.tomcat", module = "tomcat-juli")
    }
    testImplementation("org.apache.tomcat:tomcat-jdbc:$tomcatVersion") {
        exclude(group = "org.apache.tomcat", module = "tomcat-juli")
    }
    testImplementation("org.apache.tomcat:tomcat-juli:$tomcatVersion")
    testImplementation("org.apache.tomcat:tomcat-catalina:$tomcatVersion")
    testImplementation("com.zaxxer:HikariCP:4.0.3")
    testImplementation("org.slf4j:slf4j-simple:1.7.36")
    testImplementation("com.h2database:h2:2.2.224")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile> {
    options.release.set(17)
    options.encoding = "UTF-8"
}

tasks.jar {
    manifest {
        attributes(
            "Manifest-Version" to "1.0",
            "Main-Class" to "umrao.tomcat.vault.cli.TomcatVaultCLI",
            "Implementation-Title" to "Tomcat Vault",
            "Implementation-Version" to project.version
        )
    }
    archiveBaseName.set("tomcat-vault")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
        csv.required.set(true)
    }
}

jacoco {
    toolVersion = "0.8.12"
}
