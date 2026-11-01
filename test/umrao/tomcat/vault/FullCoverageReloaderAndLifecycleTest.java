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

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import umrao.tomcat.vault.audit.VaultAuditLogger;
import umrao.tomcat.vault.jmx.VaultJmxSanitizer;
import umrao.tomcat.vault.jmx.VaultStatus;
import umrao.tomcat.vault.listener.VaultLifecycleListener;
import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;
import umrao.tomcat.vault.refresh.VaultCredentialReloader;
import umrao.tomcat.vault.secret.SecretResolver;
import umrao.tomcat.vault.secret.SecretResolverRegistry;

import java.io.File;
import java.nio.file.Path;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Vivek Umrao
 */
public class FullCoverageReloaderAndLifecycleTest {

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        System.clearProperty(VaultConstants.SYS_PROP_LOG_FILE);
        System.clearProperty(VaultConstants.SYS_PROP_LOG_DEBUG);
        System.clearProperty("catalina.base");
        System.clearProperty("catalina.home");
    }

    @AfterEach
    void tearDown() {
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        System.clearProperty(VaultConstants.SYS_PROP_LOG_FILE);
        System.clearProperty(VaultConstants.SYS_PROP_LOG_DEBUG);
        System.clearProperty("catalina.base");
        System.clearProperty("catalina.home");
        VaultStatus.unregisterMBean();
    }

    // Pool Mocks for Eviction Testing
    @SuppressWarnings("unused")
    public static class TomcatJdbcPoolMock {
        boolean purged = false;
        public void purge() { purged = true; }
    }

    @SuppressWarnings("unused")
    public static class Dbcp2RestartMock {
        boolean restarted = false;
        public void restart() { restarted = true; }
    }

    @SuppressWarnings("unused")
    public static class Dbcp2EvictMock {
        boolean evicted = false;
        public void evict() { evicted = true; }
    }

    @SuppressWarnings("unused")
    public static class GenericEvictMock {
        boolean evicted = false;
        public void evictConnections() { evicted = true; }
    }

    @SuppressWarnings("unused")
    public static class FailingPoolMock {
        public void purge() { throw new RuntimeException("Eviction simulated failure"); }
    }

    @Test
    void testVaultCredentialReloaderEdgeCases() {
        VaultCredentialReloader reloader = VaultCredentialReloader.getInstance();

        // Null and invalid registrations
        reloader.registerDataSource(null, null);
        reloader.registerDataSource("ds1", null);
        reloader.registerDataSource(null, new Object());

        // Unregister non-existent and null
        reloader.unregisterDataSource(null);
        reloader.unregisterDataSource("non-existent-ds");

        // Register and unregister valid
        Object ds = new Object();
        reloader.registerDataSource("jdbc/MyTestDS", ds);
        assertTrue(reloader.getRegisteredDataSourceCount() > 0);
        reloader.unregisterDataSource("jdbc/MyTestDS");

        // Test pool eviction for different pool types
        TomcatJdbcPoolMock tomcatPool = new TomcatJdbcPoolMock();
        Dbcp2RestartMock dbcp2Restart = new Dbcp2RestartMock();
        Dbcp2EvictMock dbcp2Evict = new Dbcp2EvictMock();
        GenericEvictMock genericPool = new GenericEvictMock();
        FailingPoolMock failingPool = new FailingPoolMock();

        reloader.registerDataSource("jdbc/TomcatPool", tomcatPool);
        reloader.registerDataSource("jdbc/Dbcp2Restart", dbcp2Restart);
        reloader.registerDataSource("jdbc/Dbcp2Evict", dbcp2Evict);
        reloader.registerDataSource("jdbc/GenericPool", genericPool);
        reloader.registerDataSource("jdbc/FailingPool", failingPool);

        // Reload credentials triggers evictPoolConnections on all
        reloader.notifyReload("*");

        assertTrue(tomcatPool.purged);
        assertTrue(dbcp2Restart.restarted);
        assertTrue(dbcp2Evict.evicted);
        assertTrue(genericPool.evicted);

        // Duplicate registration check
        reloader.registerDataSource("jdbc/TomcatPool", tomcatPool);
    }

    @Test
    void testVaultLifecycleListenerBranches() {
        VaultLifecycleListener listener = new VaultLifecycleListener();
        listener.setJmxEnabled(true);

        Lifecycle dummy = new org.apache.catalina.util.LifecycleBase() {
            @Override protected void initInternal() {}
            @Override protected void startInternal() {}
            @Override protected void stopInternal() {}
            @Override protected void destroyInternal() {}
        };

        // Null event and null type
        listener.lifecycleEvent(null);
        listener.lifecycleEvent(new LifecycleEvent(dummy, null, null));

        // Start event with production key
        System.setProperty(VaultConstants.SYS_PROP_KEY, "my-production-key-12345");
        listener.lifecycleEvent(new LifecycleEvent(dummy, Lifecycle.BEFORE_START_EVENT, null));
        listener.lifecycleEvent(new LifecycleEvent(dummy, Lifecycle.START_EVENT, null));

        // Stop events
        listener.lifecycleEvent(new LifecycleEvent(dummy, Lifecycle.STOP_EVENT, null));
        listener.lifecycleEvent(new LifecycleEvent(dummy, Lifecycle.AFTER_STOP_EVENT, null));

        // Start event with jmxEnabled = false
        listener.setJmxEnabled(false);
        listener.lifecycleEvent(new LifecycleEvent(dummy, Lifecycle.START_EVENT, null));
        listener.lifecycleEvent(new LifecycleEvent(dummy, Lifecycle.STOP_EVENT, null));
    }

    @Test
    void testVaultAuditLoggerEscapesAndException() {
        VaultAuditLogger logger = new VaultAuditLogger();

        // null escape
        assertEquals("", VaultAuditLogger.escapeJson(null));

        // all escape branches
        String testStr = "quotes:\" backslash:\\ backspace:\b formfeed:\f newline:\n carriage:\r tab:\t ctrl:\u0001";
        String escaped = VaultAuditLogger.escapeJson(testStr);
        assertTrue(escaped.contains("\\\""));
        assertTrue(escaped.contains("\\\\"));
        assertTrue(escaped.contains("\\b"));
        assertTrue(escaped.contains("\\f"));
        assertTrue(escaped.contains("\\n"));
        assertTrue(escaped.contains("\\r"));
        assertTrue(escaped.contains("\\t"));
        assertTrue(escaped.contains("\\u0001"));

        // Consumer throwing exception
        logger.setEventConsumer(msg -> { throw new RuntimeException("Audit delivery failed"); });
        assertDoesNotThrow(() -> logger.logEvent("TEST", "res", "prop", "prov", "OK", 10));

        // Set null consumer resets to default
        logger.setEventConsumer(null);
        assertDoesNotThrow(() -> logger.logEvent("TEST", "res", "prop", "prov", "OK", 10));
    }

    @Test
    void testVaultStatusBranches() {
        VaultStatus status = VaultStatus.getInstance();

        // Double register MBean
        VaultStatus.registerMBean();
        VaultStatus.registerMBean();

        // Getters
        assertNotNull(status.getActiveKeyProvider());
        assertFalse(status.isStrictMode());
        assertTrue(status.getReloadListenerCount() >= 0);

        // Status action methods
        status.clearKeyCache();
        status.reloadCredentials("*");

        // Unregister MBean
        VaultStatus.unregisterMBean();
        VaultStatus.unregisterMBean(); // idempotent

        // Strict mode branch
        System.setProperty(VaultConstants.SYS_PROP_STRICT, "true");
        assertTrue(status.isStrictMode());
    }

    @Test
    void testVaultJmxSanitizerEmptyBranches() {
        assertEquals(Collections.emptyMap(), VaultJmxSanitizer.sanitizeAttributes(Collections.emptyMap()));
        assertEquals(Collections.emptyMap(), VaultJmxSanitizer.sanitizeAttributes(null));
        assertEquals("", VaultJmxSanitizer.sanitizeUrl(""));
        assertNull(VaultJmxSanitizer.sanitizeUrl(null));
    }

    @Test
    void testSecretResolverRegistryBranches() {
        SecretResolverRegistry registry = SecretResolverRegistry.getInstance();

        // Null and empty checks
        assertNull(registry.resolve(null));
        assertEquals("", registry.resolve(""));
        assertEquals("   ", registry.resolve("   "));
        assertFalse(registry.isResolvable(null));
        assertFalse(registry.isResolvable(""));
        assertFalse(registry.hasResolvable(null));
        assertFalse(registry.hasResolvable(""));
        assertNull(registry.resolveEmbedded(null));
        assertEquals("", registry.resolveEmbedded(""));

        // Register / unregister null
        registry.registerResolver(null);
        registry.unregisterResolver(null);

        // StandardCloudSecretResolver expressions
        SecretResolver cloudResolver = new SecretResolverRegistry.StandardCloudSecretResolver();
        assertEquals("StandardCloudSecretResolver", cloudResolver.getResolverName());
        assertFalse(cloudResolver.supports(null));
        assertTrue(cloudResolver.supports("AWS_SECRET(my-secret)"));
        assertTrue(cloudResolver.supports("VAULT(my-secret)"));
        assertTrue(cloudResolver.supports("AZURE_VAULT(my-secret)"));
        assertTrue(cloudResolver.supports("GCP_SECRET(my-secret)"));
        assertFalse(cloudResolver.supports("OTHER(my-secret)"));

        // Malformed parentheses
        assertEquals("AWS_SECRET(", cloudResolver.resolve("AWS_SECRET("));

        // System property resolution
        System.setProperty("aws.secret.my.db.pass", "secretPassFromSysProp");
        assertEquals("secretPassFromSysProp", cloudResolver.resolve("AWS_SECRET(my/db#pass)"));

        // Clear and reset
        registry.clearResolvers();
        assertFalse(registry.isResolvable("AWS_SECRET(my-secret)"));
        registry.resetDefaultResolvers();
        assertTrue(registry.isResolvable("AWS_SECRET(my-secret)"));
    }

    @Test
    void testVaultLogFactoryFileLoggingBranches() {
        // Auto configure with catalina.base debug log
        File logsDir = new File(tempDir.toFile(), "logs");
        assertTrue(logsDir.mkdirs() || logsDir.exists());
        System.setProperty("catalina.base", tempDir.toFile().getAbsolutePath());
        System.setProperty(VaultConstants.SYS_PROP_LOG_DEBUG, "true");

        // Force reconfigure
        VaultLogFactory.closeFileHandlers();
        VaultLog log = VaultLogFactory.getLog(FullCoverageReloaderAndLifecycleTest.class);
        log.info("Test message to file");
        log.error("Test severe error to trigger flush", new RuntimeException("Test err"));

        // Direct file init with path variable substitution
        String pathWithVar = "${catalina.base}/logs/custom.log";
        VaultLogFactory.initFileLogging(pathWithVar, true);
        log.debug("Debug msg to custom");
        log.warn("Warn msg to custom");

        VaultLogFactory.closeFileHandlers();
    }

    @Test
    void testSecretResolverRegistryDirectAndEmbeddedEdgeCases() {
        SecretResolverRegistry registry = SecretResolverRegistry.getInstance();

        // 1. hasResolvable with direct isResolvable expression (line 149)
        System.setProperty("aws.secret.direct.pass", "directSecret123");
        assertTrue(registry.hasResolvable("AWS_SECRET(direct/pass)"));

        // 2. resolveEmbedded with direct expression (line 166)
        assertEquals("directSecret123", registry.resolveEmbedded("AWS_SECRET(direct/pass)"));

        // 3. resolveEmbedded with string containing no match (line 170)
        assertEquals("plain-no-match-string", registry.resolveEmbedded("plain-no-match-string"));

        // 4. resolveEmbedded where token is unresolvable (line 179)
        String unresolvableEmbedded = "jdbc:mysql://user:AWS_SECRET(unknown/pass)@localhost:3306/db";
        assertEquals(unresolvableEmbedded, registry.resolveEmbedded(unresolvableEmbedded));
    }

    @Test
    void testVaultLogFactorySysPropAndJuliVaultLogMethods() {
        // Test autoConfigureFileLogging with SYS_PROP_LOG_FILE (lines 200, 205, 206)
        File logFile = tempDir.resolve("sysprop-log.log").toFile();
        System.setProperty(VaultConstants.SYS_PROP_LOG_FILE, logFile.getAbsolutePath());
        VaultLogFactory.initFileLogging(logFile.getAbsolutePath(), true);

        VaultLog log = VaultLogFactory.getLog("umrao.test.sysprop");
        log.debug("Debug via sysprop config");
        log.info("Info via sysprop config");
        log.warn("Warn via sysprop config");
        log.error("Error via sysprop config", new RuntimeException("test"));

        assertNotNull(log);

        VaultLogFactory.closeFileHandlers();
    }
}
