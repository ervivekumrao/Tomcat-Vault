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

package org.apache.tomcat.vault;

import org.apache.tomcat.vault.audit.VaultAuditLogger;
import org.apache.tomcat.vault.jmx.VaultJmxSanitizer;
import org.apache.tomcat.vault.key.FileKeyProvider;
import org.apache.tomcat.vault.refresh.VaultCredentialReloader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

public class FeaturesTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Feature 5: VaultCredentialReloader registers listeners and broadcasts reload events")
    void testCredentialReloader() {
        VaultCredentialReloader reloader = VaultCredentialReloader.getInstance();
        reloader.clearListeners();

        AtomicBoolean listenerCalled = new AtomicBoolean(false);
        AtomicReference<String> targetResource = new AtomicReference<>();

        VaultCredentialReloader.CredentialChangeListener listener = resource -> {
            listenerCalled.set(true);
            targetResource.set(resource);
        };

        reloader.addListener(listener);
        assertEquals(1, reloader.getListenerCount());

        reloader.notifyReload("jdbc/ProductionDB");
        assertTrue(listenerCalled.get());
        assertEquals("jdbc/ProductionDB", targetResource.get());

        // Exception in listener is caught gracefully
        reloader.addListener(res -> {
            throw new RuntimeException("Simulated error in listener");
        });
        assertDoesNotThrow(() -> reloader.notifyReload("jdbc/AppDB"));

        reloader.removeListener(listener);
        assertEquals(1, reloader.getListenerCount());
        reloader.clearListeners();
        assertEquals(0, reloader.getListenerCount());
    }

    @Test
    @DisplayName("Feature 7: VaultJmxSanitizer masks sensitive attributes and JDBC URLs with credentials")
    void testJmxSanitizer() throws Exception {
        // Private constructor reflection test
        Constructor<VaultJmxSanitizer> ctor = VaultJmxSanitizer.class.getDeclaredConstructor();
        ctor.setAccessible(true);
        assertNotNull(ctor.newInstance());

        // Sanitizing single attribute
        assertNull(VaultJmxSanitizer.sanitizeAttribute("password", null));
        assertEquals(VaultJmxSanitizer.MASK, VaultJmxSanitizer.sanitizeAttribute("password", "SecretPass123"));
        assertEquals(VaultJmxSanitizer.MASK, VaultJmxSanitizer.sanitizeAttribute("pwd", "SecretPass123"));
        assertEquals("BenignValue", VaultJmxSanitizer.sanitizeAttribute("maxActive", "BenignValue"));

        // JDBC URL credential masking
        String rawUrl = "jdbc:postgresql://dbuser:superSecretPassword@dbhost.internal:5432/proddb";
        String sanitizedUrl = VaultJmxSanitizer.sanitizeUrl(rawUrl);
        assertEquals("jdbc:postgresql://dbuser:******@dbhost.internal:5432/proddb", sanitizedUrl);
        assertFalse(sanitizedUrl.contains("superSecretPassword"));

        // Benign URL without credentials remains unchanged
        String benignUrl = "jdbc:postgresql://localhost:5432/testdb";
        assertEquals(benignUrl, VaultJmxSanitizer.sanitizeUrl(benignUrl));
        assertNull(VaultJmxSanitizer.sanitizeUrl(null));

        // Attribute map sanitization
        Map<String, Object> map = new HashMap<>();
        map.put("username", "appuser");
        map.put("password", "CleartextPassword");
        map.put("url", rawUrl);
        map.put("maxWaitMillis", 5000);

        Map<String, Object> sanitizedMap = VaultJmxSanitizer.sanitizeAttributes(map);
        assertEquals(VaultJmxSanitizer.MASK, sanitizedMap.get("password"));
        assertEquals(VaultJmxSanitizer.MASK, sanitizedMap.get("username"));
        assertEquals("jdbc:postgresql://dbuser:******@dbhost.internal:5432/proddb", sanitizedMap.get("url"));
        assertEquals(5000, sanitizedMap.get("maxWaitMillis"));

        assertTrue(VaultJmxSanitizer.sanitizeAttributes(null).isEmpty());
    }

    @Test
    @DisplayName("Feature 8: FileKeyProvider automatically reloads key when file is updated on disk (K8s Secret)")
    void testFileKeyProviderAutoReload() throws Exception {
        File keyFile = tempDir.resolve("k8s_secret.key").toFile();
        Files.write(keyFile.toPath(), "InitialKey123456789012345678901234".getBytes(StandardCharsets.UTF_8));

        FileKeyProvider provider = new FileKeyProvider(keyFile.getAbsolutePath());
        assertEquals("InitialKey123456789012345678901234", provider.getKey());

        // Update file on disk (simulate Kubernetes Secret or administrator rotation)
        Thread.sleep(100); // ensure file timestamp differs
        Files.write(keyFile.toPath(), "UpdatedRotatedKey9876543210987654321".getBytes(StandardCharsets.UTF_8));
        keyFile.setLastModified(System.currentTimeMillis() + 1000);

        String reloadedKey = provider.getKey();
        assertEquals("UpdatedRotatedKey9876543210987654321", reloadedKey);
    }

    @Test
    @DisplayName("Feature 9: VaultAuditLogger formats and delivers SIEM structured JSON events")
    void testAuditLogger() {
        VaultAuditLogger auditLogger = VaultAuditLogger.getInstance();
        AtomicReference<String> emittedJson = new AtomicReference<>();

        auditLogger.setEventConsumer(emittedJson::set);

        auditLogger.logEvent(
                "CREDENTIAL_DECRYPTED",
                "jdbc/FinanceDB",
                "password",
                "EnvironmentKeyProvider[TOMCAT_VAULT_KEY]",
                "SUCCESS",
                12L
        );

        String json = emittedJson.get();
        assertNotNull(json);
        assertTrue(json.contains("\"event\":\"CREDENTIAL_DECRYPTED\""));
        assertTrue(json.contains("\"resource\":\"jdbc/FinanceDB\""));
        assertTrue(json.contains("\"property\":\"password\""));
        assertTrue(json.contains("\"status\":\"SUCCESS\""));
        assertTrue(json.contains("\"duration_ms\":12"));

        // Reset to default consumer
        auditLogger.setEventConsumer(null);
        assertDoesNotThrow(() -> auditLogger.logEvent("TEST", "res", "prop", "prov", "OK", 1));
    }
}
