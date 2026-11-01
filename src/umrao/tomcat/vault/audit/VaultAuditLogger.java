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

package umrao.tomcat.vault.audit;

import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Security Information and Event Management (SIEM) Audit Logger.
 * Emits structured JSON audit records for security-relevant operations
 * (credential decryption, key retrieval, verification results) without ever logging plaintext credentials.
 */
@SuppressWarnings("unused")
public class VaultAuditLogger {

    private static final Logger LOGGER = Logger.getLogger(VaultAuditLogger.class.getName());
    private static final VaultAuditLogger INSTANCE = new VaultAuditLogger();

    private volatile Consumer<String> eventConsumer;

    public static VaultAuditLogger getInstance() {
        return INSTANCE;
    }

    public VaultAuditLogger() {
        this.eventConsumer = msg -> LOGGER.log(Level.INFO, msg);
    }

    public void setEventConsumer(Consumer<String> consumer) {
        this.eventConsumer = consumer != null ? consumer : (msg -> LOGGER.log(Level.INFO, msg));
    }

    /**
     * Emits a structured audit event.
     *
     * @param eventType type of event (e.g. CREDENTIAL_DECRYPTED, VERIFICATION_SUCCESS, DECRYPTION_FAILURE)
     * @param resource JNDI resource identifier (e.g. "jdbc/AppDB")
     * @param property property key (e.g. "password", "username")
     * @param provider key provider or mechanism used
     * @param status SUCCESS or FAILURE
     * @param durationMs duration in milliseconds
     */
    public void logEvent(String eventType, String resource, String property, String provider, String status, long durationMs) {
        String timestamp = java.time.Instant.now().toString();

        String json = "{"
                + "\"timestamp\":\"" + timestamp + "\","
                + "\"event\":\"" + escapeJson(eventType) + "\","
                + "\"resource\":\"" + escapeJson(resource) + "\","
                + "\"property\":\"" + escapeJson(property) + "\","
                + "\"provider\":\"" + escapeJson(provider) + "\","
                + "\"status\":\"" + escapeJson(status) + "\","
                + "\"duration_ms\":" + durationMs
                + "}";

        try {
            if (eventConsumer != null) {
                eventConsumer.accept(json);
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Failed to deliver audit event: " + e.getMessage(), e);
        }
    }

    public static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 32) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
