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

import umrao.tomcat.vault.key.KeyProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class VaultCryptoTest {

    private VaultCrypto crypto;

    @BeforeEach
    public void setUp() {
        crypto = new VaultCrypto("TestPassphraseKey1234567890!");
    }

    @Test
    @DisplayName("Constructors branch coverage")
    public void testConstructors() {
        VaultCrypto defaultCrypto = new VaultCrypto();
        assertNotNull(defaultCrypto);

        VaultCrypto nullProviderCrypto = new VaultCrypto((KeyProvider) null);
        assertNotNull(nullProviderCrypto);

        VaultCrypto explicitKeyCrypto = new VaultCrypto("ExplicitPassKey");
        assertNotNull(explicitKeyCrypto);
        assertEquals("ExplicitPassKey", explicitKeyCrypto.getKeyProvider().getKey());
        assertEquals("ExplicitKeyProvider", explicitKeyCrypto.getKeyProvider().getProviderName());

        // Test exception catch block in encrypt and encryptLegacy
        VaultCrypto failingCrypto = new VaultCrypto(new KeyProvider() {
            @Override
            public String getKey() {
                throw new RuntimeException("Forced key failure");
            }

            @Override
            public String getProviderName() {
                return "FailingProvider";
            }
        });
        assertThrows(RuntimeException.class, () -> failingCrypto.encrypt("ValidMessage"));
        assertThrows(RuntimeException.class, () -> failingCrypto.encryptLegacy("ValidMessage"));
    }

    @Test
    @DisplayName("Encrypt and decrypt round trip with modern AES-256-GCM")
    public void testEncryptDecryptRoundTrip() {
        String secret = "MyS3cret_P@ssw0rd!#%&";
        String encrypted = crypto.encrypt(secret);

        assertNotNull(encrypted);
        assertTrue(encrypted.startsWith("ENC("), "Must start with ENC(");
        assertTrue(encrypted.endsWith(")"), "Must end with )");

        String decrypted = crypto.decrypt(encrypted);
        assertEquals(secret, decrypted, "Decrypted message must match original plaintext");
    }

    @Test
    @DisplayName("Dynamic IV ensures distinct ciphertexts for identical plaintexts")
    public void testDynamicIvProducesDifferentCiphertexts() {
        String secret = "SamePasswordTwice";
        String enc1 = crypto.encrypt(secret);
        String enc2 = crypto.encrypt(secret);

        assertNotEquals(enc1, enc2, "CBC/GCM must generate unique IV per encryption");
        assertEquals(secret, crypto.decrypt(enc1));
        assertEquals(secret, crypto.decrypt(enc2));
    }

    @Test
    @DisplayName("Unicode and multi-byte character support (currency, umlauts, accents)")
    public void testUnicodeAndSpecialCharacters() {
        String unicodeSecret = "Pä$$wörd_€_¥_123_™_©";
        String encrypted = crypto.encrypt(unicodeSecret);
        String decrypted = crypto.decrypt(encrypted);

        assertEquals(unicodeSecret, decrypted);
    }

    @Test
    @DisplayName("Tampered ciphertext fails authenticated GCM tag verification")
    public void testTamperedCiphertextFails() {
        String encrypted = crypto.encrypt("SensitiveDatabasePassword");
        // Tamper with one character in the payload
        String tampered = encrypted.substring(0, 10) + "X" + encrypted.substring(11);

        assertThrows(RuntimeException.class, () -> crypto.decrypt(tampered));
    }

    @Test
    @DisplayName("Null and empty handling in encrypt and decrypt")
    public void testNullAndEmptyInputs() {
        assertThrows(IllegalArgumentException.class, () -> crypto.encrypt(null));
        assertThrows(IllegalArgumentException.class, () -> crypto.encrypt(""));

        assertNull(crypto.decrypt(null));
        assertEquals("", crypto.decrypt(""));

        assertFalse(crypto.isEncrypted(null));
        assertFalse(crypto.isEncrypted(""));
        assertFalse(crypto.isEncrypted("plainString"));
        assertFalse(crypto.isEncrypted("ENC()")); // too short
        assertTrue(crypto.isEncrypted("ENC(validPayload)"));
        assertTrue(crypto.isEncrypted("someData" + VaultConstants.LEGACY_HEX_IDENTIFIER));
        assertTrue(crypto.isEncrypted("someData" + VaultConstants.LEGACY_ENCRYPTION_IDENTIFIER));
    }

    @Test
    @DisplayName("decryptModern short payload error handling")
    public void testDecryptModernShortPayload() {
        // Less than 28 bytes (12 IV + 16 Tag)
        String shortBase64 = Base64.getEncoder().encodeToString(new byte[10]);
        assertThrows(RuntimeException.class, () -> crypto.decrypt("ENC(" + shortBase64 + ")"));
    }

    @Test
    @DisplayName("Plaintext strings pass through unchanged")
    public void testPlaintextPassThrough() {
        String plain = "oracle.jdbc.OracleDriver";
        assertEquals(plain, crypto.decrypt(plain));
    }

    @Test
    @DisplayName("Legacy format encryption and decryption backward compatibility")
    public void testLegacyFormatDecryption() {
        VaultCrypto legacyCrypto = new VaultCrypto(VaultConstants.DEFAULT_DEV_KEY);
        String secret = "legacyDatabasePassword123";
        String legacyEncrypted = legacyCrypto.encryptLegacy(secret);

        String decrypted = legacyCrypto.decrypt(legacyEncrypted);
        assertEquals(secret, decrypted);

        // Test decryptLegacy edge cases
        assertNull(legacyCrypto.decryptLegacy(null));
        assertEquals("", legacyCrypto.decryptLegacy(""));
        assertEquals("plainTextNoMarker", legacyCrypto.decryptLegacy("plainTextNoMarker"));

        // Hex string that does not end with marker after decoding
        String nonMarkerHex = VaultCrypto.safeStringToHex("justSomePlainText");
        assertEquals(nonMarkerHex, legacyCrypto.decryptLegacy(nonMarkerHex));

        // Corrupted legacy ciphertext ending with marker
        assertThrows(RuntimeException.class, () ->
                legacyCrypto.decryptLegacy("corruptedBase64!@" + VaultConstants.LEGACY_ENCRYPTION_IDENTIFIER));

        // encryptLegacy validation
        assertThrows(IllegalArgumentException.class, () -> legacyCrypto.encryptLegacy(null));
        assertThrows(IllegalArgumentException.class, () -> legacyCrypto.encryptLegacy(""));
    }

    @Test
    @DisplayName("Safe Hex conversion does not drop leading zeros or corrupt byte boundaries")
    public void testSafeHexConversions() {
        String testString = "Hello \u0001\u0002\n World € 123";
        String hex = VaultCrypto.safeStringToHex(testString);
        assertNotNull(hex);
        assertEquals(0, hex.length() % 2, "Hex length must be even");

        String decoded = VaultCrypto.safeHexToString(hex);
        assertEquals(testString, decoded);

        // Edge cases
        assertNull(VaultCrypto.safeStringToHex(null));
        assertNull(VaultCrypto.safeHexToString(null));
        assertEquals("", VaultCrypto.safeHexToString(""));
        assertThrows(IllegalArgumentException.class, () -> VaultCrypto.safeHexToString("A")); // odd length
        assertThrows(IllegalArgumentException.class, () -> VaultCrypto.safeHexToString("0G")); // non-hex character
    }

    @Test
    @DisplayName("64-character raw hex key direct derivation")
    public void test64CharacterHexKey() {
        String hexKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        VaultCrypto hexCrypto = new VaultCrypto(hexKey);
        String secret = "HexSecretTest";
        String enc = hexCrypto.encrypt(secret);
        assertEquals(secret, hexCrypto.decrypt(enc));
    }

    @Test
    @DisplayName("Provider returning null or empty resolves to default development key")
    public void testResolveSecretKeyFallback() {
        VaultCrypto emptyProviderCrypto = new VaultCrypto(new KeyProvider() {
            @Override
            public String getKey() {
                return "   ";
            }

            @Override
            public String getProviderName() {
                return "BlankKeyProvider";
            }
        });
        String enc = emptyProviderCrypto.encrypt("FallbackTest");
        assertEquals("FallbackTest", emptyProviderCrypto.decrypt(enc));
    }

    @Test
    @DisplayName("VaultConstants private constructor reflection test")
    public void testVaultConstantsConstructor() throws Exception {
        Constructor<VaultConstants> constructor = VaultConstants.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        constructor.setAccessible(true);
        VaultConstants instance = constructor.newInstance();
        assertNotNull(instance);

        assertEquals("AES/GCM/NoPadding", VaultConstants.ALGORITHM_AES_GCM);
        assertEquals("AES/CBC/PKCS5Padding", VaultConstants.ALGORITHM_AES_CBC_LEGACY);
    }

    @Test
    @DisplayName("isHex64 and custom salt derivation coverage")
    public void testIsHex64AndSalt() {
        assertFalse(VaultCrypto.isHex64(null));
        assertFalse(VaultCrypto.isHex64("short"));
        assertFalse(VaultCrypto.isHex64("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"));
        assertTrue(VaultCrypto.isHex64("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

        System.setProperty(VaultConstants.SYS_PROP_SALT, "MyCustomEnterpriseSalt2026");
        try {
            VaultCrypto saltCrypto = new VaultCrypto("MyPassphraseWithCustomSalt");
            String enc = saltCrypto.encrypt("SaltPlainText");
            assertEquals("SaltPlainText", saltCrypto.decrypt(enc));
        } finally {
            System.clearProperty(VaultConstants.SYS_PROP_SALT);
        }
    }

    @Test
    @DisplayName("VaultCrypto: 32-byte Base64 key direct derivation bypasses PBKDF2")
    public void testBase64Key32DirectDerivation() {
        byte[] rawKey = new byte[32];
        for (int i = 0; i < 32; i++) {
            rawKey[i] = (byte) (i + 1);
        }
        String b64Key = Base64.getEncoder().encodeToString(rawKey);
        assertTrue(VaultCrypto.isBase64Key32(b64Key));
        assertFalse(VaultCrypto.isBase64Key32(null));
        assertFalse(VaultCrypto.isBase64Key32("short"));
        assertFalse(VaultCrypto.isBase64Key32("01234567890123456789012345678901234567890123")); // 44 chars no =

        VaultCrypto b64Crypto = new VaultCrypto(b64Key);
        String plaintext = "DirectBase64KeyTestString123!";
        String enc = b64Crypto.encrypt(plaintext);
        assertEquals(plaintext, b64Crypto.decrypt(enc));

        // Test with AAD
        byte[] aad = "custom-aad-context".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String encAad = b64Crypto.encrypt(plaintext, "v1", aad);
        assertEquals(plaintext, b64Crypto.decrypt(encAad, aad));

        // Tampered AAD fails decryption
        byte[] wrongAad = "wrong-aad-context".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertThrows(umrao.tomcat.vault.exception.DecryptionException.class, () -> b64Crypto.decrypt(encAad, wrongAad));

        // Clear key cache
        assertDoesNotThrow(VaultCrypto::clearKeyCache);
    }
}

