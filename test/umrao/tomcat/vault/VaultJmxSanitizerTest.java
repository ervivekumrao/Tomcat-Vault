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

package umrao.tomcat.vault;

import umrao.tomcat.vault.jmx.VaultJmxSanitizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class VaultJmxSanitizerTest {

    @Test
    @DisplayName("VaultJmxSanitizer masks sensitive attributes and JDBC URLs with credentials")
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
        map.put("apiKey", "KeySecretABC123");
        map.put("clientSecret", "SecretOAuth456");
        map.put("token", "JWT.Token.789");
        map.put("maxWaitMillis", 5000);

        Map<String, Object> sanitizedMap = VaultJmxSanitizer.sanitizeAttributes(map);
        assertEquals(VaultJmxSanitizer.MASK, sanitizedMap.get("password"));
        assertEquals(VaultJmxSanitizer.MASK, sanitizedMap.get("username"));
        assertEquals(VaultJmxSanitizer.MASK, sanitizedMap.get("apiKey"));
        assertEquals(VaultJmxSanitizer.MASK, sanitizedMap.get("clientSecret"));
        assertEquals(VaultJmxSanitizer.MASK, sanitizedMap.get("token"));
        assertEquals("jdbc:postgresql://dbuser:******@dbhost.internal:5432/proddb", sanitizedMap.get("url"));
        assertEquals(5000, sanitizedMap.get("maxWaitMillis"));

        assertTrue(VaultJmxSanitizer.sanitizeAttributes(null).isEmpty());
    }
}
