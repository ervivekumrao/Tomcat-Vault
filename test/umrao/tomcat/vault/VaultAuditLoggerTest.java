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

import umrao.tomcat.vault.audit.VaultAuditLogger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Vivek Umrao
 */
public class VaultAuditLoggerTest {

    @AfterEach
    void tearDown() {
        VaultAuditLogger.getInstance().setEventConsumer(null);
    }

    @Test
    @DisplayName("VaultAuditLogger formats and delivers SIEM structured JSON events")
    void testAuditLogger() {
        VaultAuditLogger auditLogger = VaultAuditLogger.getInstance();
        AtomicReference<String> emittedJson = new AtomicReference<>();

        auditLogger.setEventConsumer(emittedJson::set);

        auditLogger.logEvent(
                "CREDENTIAL_DECRYPTED",
                "jdbc/FinanceDB\nwith\"quotes\"",
                "password\tkey",
                "EnvironmentKeyProvider[TOMCAT_VAULT_KEY]",
                "SUCCESS",
                12L
        );

        String json = emittedJson.get();
        assertNotNull(json);
        assertTrue(json.contains("\"event\":\"CREDENTIAL_DECRYPTED\""));
        assertTrue(json.contains("\"resource\":\"jdbc/FinanceDB\\nwith\\\"quotes\\\"\""));
        assertTrue(json.contains("\"property\":\"password\\tkey\""));
        assertTrue(json.contains("\"status\":\"SUCCESS\""));
        assertTrue(json.contains("\"duration_ms\":12"));

        // Reset to default consumer
        auditLogger.setEventConsumer(null);
        assertDoesNotThrow(() -> auditLogger.logEvent("TEST", "res", "prop", "prov", "OK", 1));
    }
}
