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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import umrao.tomcat.vault.exception.DecryptionException;
import umrao.tomcat.vault.exception.SecretResolutionException;
import umrao.tomcat.vault.key.KeyProvider;
import umrao.tomcat.vault.secret.SecretResolver;
import umrao.tomcat.vault.secret.SecretResolverRegistry;

import javax.crypto.SecretKey;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Vector;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Vivek Umrao
 */
public class FullCoverageCryptoAndDecryptorTest {

    @BeforeEach
    void setUp() {
        System.clearProperty(VaultConstants.SYS_PROP_PBKDF2_ITERATIONS);
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        System.clearProperty(VaultConstants.SYS_PROP_SALT);
    }

    @AfterEach
    void tearDown() {
        System.clearProperty(VaultConstants.SYS_PROP_PBKDF2_ITERATIONS);
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        System.clearProperty(VaultConstants.SYS_PROP_SALT);
    }

    @Test
    void testVaultCryptoCacheEvictionBranches() {
        VaultCrypto.clearKeyCache();

        // Fill cache up to 128 entries to trigger bounded cache eviction
        for (int i = 0; i < 135; i++) {
            SecretKey k1 = VaultCrypto.getOrCreateGcmSecretKey("passphrase-eviction-" + i);
            assertNotNull(k1);
            SecretKey k2 = VaultCrypto.getOrCreateLegacyCbcSecretKey("passphrase-legacy-" + i);
            assertNotNull(k2);
        }
    }

    @Test
    void testVaultCryptoIterationsAndSaltBranches() {
        // Test custom salt
        System.setProperty(VaultConstants.SYS_PROP_SALT, "CustomSalt12345");
        VaultCrypto crypto = new VaultCrypto("my-test-key");
        String enc = crypto.encrypt("hello");
        assertEquals("hello", crypto.decrypt(enc));

        // Test PBKDF2 iterations parsing
        System.setProperty(VaultConstants.SYS_PROP_PBKDF2_ITERATIONS, "1500");
        SecretKey k1 = VaultCrypto.getOrCreateGcmSecretKey("test-iter-1500");
        assertNotNull(k1);

        // Invalid iteration number (falls back to default)
        System.setProperty(VaultConstants.SYS_PROP_PBKDF2_ITERATIONS, "invalid-num");
        SecretKey k2 = VaultCrypto.getOrCreateGcmSecretKey("test-iter-invalid");
        assertNotNull(k2);

        // Iteration number below 1000 (falls back to default)
        System.setProperty(VaultConstants.SYS_PROP_PBKDF2_ITERATIONS, "500");
        SecretKey k3 = VaultCrypto.getOrCreateGcmSecretKey("test-iter-500");
        assertNotNull(k3);
    }

    @Test
    void testVaultCryptoHexAndBase64EdgeCases() {
        // safeBytesToHex and safeStringToHex with null
        assertNull(VaultCrypto.safeBytesToHex(null));
        assertNull(VaultCrypto.safeStringToHex(null));

        // safeHexToString with null, empty, odd length, invalid chars
        assertNull(VaultCrypto.safeHexToString(null));
        assertEquals("", VaultCrypto.safeHexToString(""));
        assertThrows(IllegalArgumentException.class, () -> VaultCrypto.safeHexToString("A"));
        assertThrows(IllegalArgumentException.class, () -> VaultCrypto.safeHexToString("ZZ"));

        // isBase64Key32 branch testing
        // Non-32 byte base64 (e.g. 16 bytes = 24 chars)
        byte[] b16 = new byte[16];
        String b64_16 = Base64.getEncoder().encodeToString(b16);
        SecretKey key16 = VaultCrypto.getOrCreateGcmSecretKey(b64_16);
        assertNotNull(key16);

        // Invalid base64 string
        SecretKey keyInvalid = VaultCrypto.getOrCreateGcmSecretKey("!!!NOT_BASE64!!!");
        assertNotNull(keyInvalid);
    }

    @Test
    void testVaultCryptoDecryptEmbeddedEdgeCases() {
        VaultCrypto crypto = new VaultCrypto("embedded-test-key");

        // Null and empty
        assertNull(crypto.decryptEmbedded(null));
        assertEquals("", crypto.decryptEmbedded(""));

        // String without ENC(...)
        assertEquals("jdbc:mysql://localhost:3306/db", crypto.decryptEmbedded("jdbc:mysql://localhost:3306/db"));

        // String with valid ENC(...)
        String enc = crypto.encrypt("mypassword");
        String embedded = "jdbc:mysql://user:" + enc + "@localhost:3306/db";
        assertEquals("jdbc:mysql://user:mypassword@localhost:3306/db", crypto.decryptEmbedded(embedded));

        // String with unresolvable/malformed ENC
        String malformedEmbedded = "prefix-ENC(INVALID_DATA)-suffix";
        assertThrows(DecryptionException.class, () -> crypto.decryptEmbedded(malformedEmbedded));
    }

    @Test
    void testVaultCryptoStrictModeKeyValidation() {
        // KeyProvider returning null in strict mode
        KeyProvider nullProvider = new KeyProvider() {
            @Override public String getKey() { return null; }
            @Override public String getKey(String alias) { return null; }
            @Override public String getProviderName() { return "NullProvider"; }
        };

        System.setProperty(VaultConstants.SYS_PROP_STRICT, "true");
        VaultCrypto strictCrypto = new VaultCrypto(nullProvider);
        assertThrows(SecurityException.class, () -> strictCrypto.encrypt("test"));
    }

    @Test
    void testReferencePropertyDecryptorEdgeCases() throws Exception {
        VaultCrypto crypto = new VaultCrypto("decryptor-edge-key");
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor(crypto);

        // Reference with null className and null refAddr
        Reference ref = new Reference(null) {
            private final Vector<RefAddr> addrs = new Vector<>();
            {
                addrs.add(null); // null refAddr
                addrs.add(new StringRefAddr("unrelated", "plain"));
                addrs.add(new StringRefAddr(null, "val")); // null type
                addrs.add(new StringRefAddr("emptyVal", null)); // null content
            }
            @Override
            public Enumeration<RefAddr> getAll() {
                return addrs.elements();
            }
        };

        decryptor.decryptProperties(ref);

        // Test DecryptionException on corrupted ciphertext
        Reference badRef = new Reference("javax.sql.DataSource");
        badRef.add(new StringRefAddr("password", "ENC(CORRUPTED_CIPHERTEXT)"));
        assertThrows(DecryptionException.class, () -> decryptor.decryptProperties(badRef));

        // Test DecryptionException on embedded corrupted ciphertext
        Reference embeddedBadRef = new Reference("javax.sql.DataSource");
        embeddedBadRef.add(new StringRefAddr("url", "jdbc:postgresql://user:ENC(INVALID_DATA)@localhost/db"));
        assertThrows(DecryptionException.class, () -> decryptor.decryptProperties(embeddedBadRef));

        // Test with null KeyProvider on VaultCrypto (line 77)
        VaultCrypto cryptoNoProvider = new VaultCrypto();
        java.lang.reflect.Field kpField = VaultCrypto.class.getDeclaredField("keyProvider");
        kpField.setAccessible(true);
        kpField.set(cryptoNoProvider, null);
        ReferencePropertyDecryptor decryptorNoProvider = new ReferencePropertyDecryptor(cryptoNoProvider);
        Reference plainRef = new Reference("javax.sql.DataSource");
        plainRef.add(new StringRefAddr("username", "myuser"));
        decryptorNoProvider.decryptProperties(plainRef);

        // Test SecretResolutionException on failing secret resolver
        SecretResolver failingResolver = new SecretResolver() {
            @Override public boolean supports(String expr) { return expr.startsWith("AWS_SECRET(") && expr.contains("fail-secret"); }
            @Override public String resolve(String expr) { throw new RuntimeException("Resolver down"); }
            @Override public String getResolverName() { return "FailingResolver"; }
        };
        SecretResolverRegistry.getInstance().registerResolver(failingResolver);

        Reference failSecretRef = new Reference("javax.sql.DataSource");
        failSecretRef.add(new StringRefAddr("password", "AWS_SECRET(fail-secret)"));
        assertThrows(SecretResolutionException.class, () -> decryptor.decryptProperties(failSecretRef));

        Reference failEmbeddedSecretRef = new Reference("javax.sql.DataSource");
        failEmbeddedSecretRef.add(new StringRefAddr("url", "jdbc:postgresql://user:AWS_SECRET(fail-secret)@localhost/db"));
        assertThrows(SecretResolutionException.class, () -> decryptor.decryptProperties(failEmbeddedSecretRef));
    }
}
