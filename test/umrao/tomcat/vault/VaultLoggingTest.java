/*
 * Copyright 2024-2026 the original author or authors (Vivek Umrao).
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

package umrao.tomcat.vault;

import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Vivek Umrao
 */
public class VaultLoggingTest {

    @TempDir
    Path tempDir;

    @AfterEach
    void tearDown() {
        VaultLogFactory.closeFileHandlers();
        System.clearProperty(VaultConstants.SYS_PROP_LOG_FILE);
        System.clearProperty(VaultConstants.SYS_PROP_LOG_DEBUG);
    }

    @Test
    @DisplayName("VaultLogFactory and VaultLog logging methods coverage")
    void testLoggingMethods() throws Exception {
        // Private constructor reflection test
        Constructor<VaultLogFactory> ctor = VaultLogFactory.class.getDeclaredConstructor();
        ctor.setAccessible(true);
        assertNotNull(ctor.newInstance());

        VaultLog log = VaultLogFactory.getLog(VaultLoggingTest.class);
        assertNotNull(log);

        // Check availability
        assertTrue(VaultLogFactory.isTomcatJuliAvailable());

        // Test logging methods
        log.info("Testing INFO log level");
        log.debug("Testing DEBUG log level");
        log.debug("Testing DEBUG with throwable", new RuntimeException("Debug exception"));
        log.warn("Testing WARN log level");
        log.warn("Testing WARN with throwable", new RuntimeException("Warn exception"));
        log.error("Testing ERROR log level");
        log.error("Testing ERROR with throwable", new RuntimeException("Error exception"));

        // Null class fallback
        VaultLog fallbackLog = VaultLogFactory.getLog((Class<?>) null);
        assertNotNull(fallbackLog);
    }

    @Test
    @DisplayName("Tomcat supported file logging to dedicated file for debugging")
    void testFileLoggingForDebugging() throws Exception {
        File debugLogFile = tempDir.resolve("tomcat-vault-debug.log").toFile();

        VaultLogFactory.initFileLogging(debugLogFile.getAbsolutePath(), true);
        assertTrue(VaultLogFactory.isFileLoggingActive());

        VaultLog log = VaultLogFactory.getLog("umrao.tomcat.vault.DebugTest");
        log.info("Message written to debug log file");
        log.error("Error written to debug log file", new IllegalArgumentException("Simulated error"));

        VaultLogFactory.closeFileHandlers();
        assertFalse(VaultLogFactory.isFileLoggingActive());

        // Verify log file was created and contains the logged message
        assertTrue(debugLogFile.exists());
        List<String> lines = Files.readAllLines(debugLogFile.toPath());
        assertFalse(lines.isEmpty());

        boolean foundInfo = false;
        boolean foundError = false;
        for (String line : lines) {
            if (line.contains("Message written to debug log file")) {
                foundInfo = true;
            }
            if (line.contains("Error written to debug log file")) {
                foundError = true;
            }
        }
        assertTrue(foundInfo, "Log file should contain info message");
        assertTrue(foundError, "Log file should contain error message");
    }

    @Test
    @DisplayName("File logging handles path variable substitution and null path")
    void testPathVariableSubstitution() {
        assertDoesNotThrow(() -> VaultLogFactory.initFileLogging(null, false));
        assertDoesNotThrow(() -> VaultLogFactory.initFileLogging("   ", false));

        System.setProperty("catalina.base", tempDir.toString());
        File subLogFile = tempDir.resolve("sub/test.log").toFile();

        VaultLogFactory.initFileLogging("${catalina.base}/sub/test.log", false);
        VaultLog log = VaultLogFactory.getLog("umrao.tomcat.vault.SubTest");
        log.info("Path variable test");

        VaultLogFactory.closeFileHandlers();
        assertTrue(subLogFile.exists());
    }

    @Test
    @DisplayName("JulVaultLog direct adapter test")
    void testJulVaultLogAdapter() {
        java.util.logging.Logger logger = java.util.logging.Logger.getLogger("test.jul");
        VaultLogFactory.JulVaultLog julLog = new VaultLogFactory.JulVaultLog("test.jul", logger);

        julLog.info("JUL info message");
        julLog.debug("JUL debug message");
        julLog.debug("JUL debug with ex", new RuntimeException("debug"));
        julLog.warn("JUL warn message");
        julLog.warn("JUL warn with ex", new RuntimeException("warn"));
        julLog.error("JUL error message");
        julLog.error("JUL error with ex", new RuntimeException("error"));

        assertNotNull(julLog);
        assertFalse(julLog.isDebugEnabled());
        assertTrue(julLog.isInfoEnabled());
    }
}
