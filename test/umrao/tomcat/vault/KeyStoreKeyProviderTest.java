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

import umrao.tomcat.vault.key.KeyStoreKeyProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class KeyStoreKeyProviderTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("KeyStoreKeyProvider loads key from PKCS12 keystore")
    void testLoadKeyFromKeyStore() throws Exception {
        File ksFile = tempDir.resolve("vault.p12").toFile();
        char[] password = "changeit".toCharArray();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);

        byte[] rawKey = "MasterSecretKeyForKeystore123456".getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKey = new SecretKeySpec(rawKey, "AES");
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.PasswordProtection protParam = new KeyStore.PasswordProtection(password);

        ks.setEntry("tomcat-vault", entry, protParam);

        byte[] rawKeyV2 = "SecondSecretKeyForRotation123456".getBytes(StandardCharsets.UTF_8);
        ks.setEntry("v2", new KeyStore.SecretKeyEntry(new SecretKeySpec(rawKeyV2, "AES")), protParam);

        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            ks.store(fos, password);
        }

        KeyStoreKeyProvider provider = new KeyStoreKeyProvider(
                ksFile.getAbsolutePath(),
                password,
                "tomcat-vault",
                "PKCS12"
        );

        String key = provider.getKey();
        assertNotNull(key);
        assertEquals(Base64.getEncoder().encodeToString(rawKey), key);

        String keyV2 = provider.getKey("v2");
        assertNotNull(keyV2);
        assertEquals(Base64.getEncoder().encodeToString(rawKeyV2), keyV2);

        // Non-existent alias
        assertNull(provider.getKey("non-existent-alias"));

        // getProviderName
        assertTrue(provider.getProviderName().contains("KeyStoreKeyProvider"));
    }

    @Test
    @DisplayName("KeyStoreKeyProvider branch coverage: missing file, wrong password, properties resolver")
    void testBranchCoverage() {
        // Missing file
        KeyStoreKeyProvider missingFileProvider = new KeyStoreKeyProvider(
                tempDir.resolve("non_existent.p12").toString(),
                "pass".toCharArray(),
                "alias",
                "PKCS12"
        );
        assertNull(missingFileProvider.getKey());

        // System property resolution
        Map<String, String> sysProps = new HashMap<>();
        sysProps.put(VaultConstants.SYS_PROP_KEYSTORE, tempDir.resolve("dummy.p12").toString());
        sysProps.put(VaultConstants.SYS_PROP_KEYSTORE_PASSWORD, "propPass");
        sysProps.put(VaultConstants.SYS_PROP_KEYSTORE_TYPE, "PKCS12");
        sysProps.put(VaultConstants.SYS_PROP_KEYSTORE_ALIAS, "propAlias");

        KeyStoreKeyProvider resolverProvider = new KeyStoreKeyProvider(
                null, null, null, null,
                sysProps::get, k -> null
        );
        // Will attempt to load dummy.p12 and return null since it doesn't exist
        assertNull(resolverProvider.getKey());

        // Default constructor
        KeyStoreKeyProvider defaultProvider = new KeyStoreKeyProvider();
        assertNull(defaultProvider.getKey());
    }
}
