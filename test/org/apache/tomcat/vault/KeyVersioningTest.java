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

import org.apache.tomcat.vault.key.CompositeKeyProvider;
import org.apache.tomcat.vault.key.EnvironmentKeyProvider;
import org.apache.tomcat.vault.key.SystemPropertyKeyProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class KeyVersioningTest {

    @AfterEach
    void tearDown() {
        System.clearProperty(VaultConstants.SYS_PROP_KEY + ".v1");
        System.clearProperty(VaultConstants.SYS_PROP_KEY + ".v2");
    }

    @Test
    @DisplayName("P2: Key Versioning round-trip encryption and decryption with key aliases")
    void testKeyVersioningRoundTrip() {
        CompositeKeyProvider provider = new CompositeKeyProvider();
        provider.registerKey("v1", "FirstVersionMasterKey123456789012");
        provider.registerKey("v2", "SecondVersionRotatedKey98765432101");

        VaultCrypto crypto = new VaultCrypto(provider);

        // Encrypt with v1
        String encryptedV1 = crypto.encrypt("DatabasePasswordV1", "v1");
        assertTrue(encryptedV1.startsWith("ENC(v1:"));
        assertTrue(encryptedV1.endsWith(")"));

        // Encrypt with v2
        String encryptedV2 = crypto.encrypt("DatabasePasswordV2", "v2");
        assertTrue(encryptedV2.startsWith("ENC(v2:"));
        assertTrue(encryptedV2.endsWith(")"));

        // Decrypt both seamlessly using the same engine
        assertEquals("DatabasePasswordV1", crypto.decrypt(encryptedV1));
        assertEquals("DatabasePasswordV2", crypto.decrypt(encryptedV2));

        // Test explicit key-alias= and alias= syntax
        String aliasedV1 = encryptedV1.replace("ENC(v1:", "ENC(key-alias=v1:");
        assertEquals("DatabasePasswordV1", crypto.decrypt(aliasedV1));

        String shortAliasedV2 = encryptedV2.replace("ENC(v2:", "ENC(alias=v2:");
        assertEquals("DatabasePasswordV2", crypto.decrypt(shortAliasedV2));
    }

    @Test
    @DisplayName("P2: SystemPropertyKeyProvider and EnvironmentKeyProvider alias resolution")
    void testAliasResolutionInProviders() {
        // System property alias
        System.setProperty(VaultConstants.SYS_PROP_KEY + ".v1", "SysPropKeyV1Value");
        SystemPropertyKeyProvider sysProvider = new SystemPropertyKeyProvider();
        assertEquals("SysPropKeyV1Value", sysProvider.getKey("v1"));

        // Env alias resolution
        Map<String, String> envMap = new HashMap<>();
        envMap.put(VaultConstants.ENV_KEY + "_PROD_KEY", "EnvProdKeyValue");
        EnvironmentKeyProvider envProvider = new EnvironmentKeyProvider(null, envMap::get);
        assertEquals("EnvProdKeyValue", envProvider.getKey("prod-key"));
    }
}
