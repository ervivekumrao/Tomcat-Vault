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
import org.apache.tomcat.vault.key.KeyProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.apache.tomcat.vault.VaultConstants.*;

/**
 * Enterprise-grade cryptographic engine supporting AES-256-GCM authenticated encryption,
 * standard ENC(...) envelope formats, dynamic random IVs, and legacy AES-CBC backward compatibility.
 */
public class VaultCrypto {

    private static final Logger LOGGER = Logger.getLogger(VaultCrypto.class.getName());
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Fixed salt for PBKDF2 key derivation from passphrase string
    private static final byte[] KDF_SALT = "ApacheTomcatVaultSaltKey2026".getBytes(StandardCharsets.UTF_8);

    // Bounded cache of derived SecretKeys to prevent unbounded memory growth (CWE-400)
    private static final int MAX_KEY_CACHE_SIZE = 128;
    private static final Map<String, SecretKey> GCM_KEY_CACHE = new ConcurrentHashMap<>();
    private static final Map<String, SecretKey> CBC_KEY_CACHE = new ConcurrentHashMap<>();

    private final KeyProvider keyProvider;

    public VaultCrypto() {
        this(new CompositeKeyProvider());
    }

    public VaultCrypto(KeyProvider keyProvider) {
        this.keyProvider = keyProvider != null ? keyProvider : new CompositeKeyProvider();
    }

    public VaultCrypto(final String explicitKey) {
        this(new KeyProvider() {
            @Override
            public String getKey() {
                return explicitKey;
            }

            @Override
            public String getProviderName() {
                return "ExplicitKeyProvider";
            }
        });
    }

    @SuppressWarnings("unused")
    public KeyProvider getKeyProvider() {
        return keyProvider;
    }

    /**
     * Encrypts a plaintext message using modern AES-256-GCM with a dynamic 12-byte IV.
     * The result is formatted as {@code ENC(Base64(IV + Ciphertext + Tag))}.
     *
     * @param plaintext cleartext string
     * @return ENC(...) envelope formatted string
     */
    public String encrypt(String plaintext) {
        return encrypt(plaintext, null);
    }

    /**
     * Encrypts a plaintext message with a specific key alias or version identifier.
     * The result is formatted as {@code ENC(keyAlias:Base64(IV + Ciphertext + Tag))}.
     *
     * @param plaintext cleartext string
     * @param keyAlias key alias or version identifier (e.g. "v1", "v2", "prod-key")
     * @return versioned ENC(...) envelope formatted string
     */
    public String encrypt(String plaintext, String keyAlias) {
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("Cannot encrypt null or empty string");
        }

        String secret = resolveSecretKeyString(keyAlias);
        SecretKey secretKey = getOrCreateGcmSecretKey(secret);

        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM_AES_GCM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextWithTag = cipher.doFinal(plaintextBytes);
            Arrays.fill(plaintextBytes, (byte) 0); // Zero out plaintext buffer in memory

            byte[] payload = new byte[iv.length + ciphertextWithTag.length];
            System.arraycopy(iv, 0, payload, 0, iv.length);
            System.arraycopy(ciphertextWithTag, 0, payload, iv.length, ciphertextWithTag.length);

            String base64Payload = Base64.getEncoder().encodeToString(payload);
            if (keyAlias != null && !keyAlias.trim().isEmpty()) {
                return PREFIX_ENC + keyAlias.trim() + ":" + base64Payload + SUFFIX_ENC;
            }
            return PREFIX_ENC + base64Payload + SUFFIX_ENC;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Encryption failed: " + e.getMessage(), e);
            throw new RuntimeException("Encryption operation failed", e);
        }
    }

    /**
     * Decrypts an encrypted property value.
     * Supports both modern {@code ENC(...)} format and legacy AES-CBC hex format.
     * If the input is not recognized as encrypted, it is returned as-is (plaintext).
     *
     * @param ciphertext encrypted envelope or plaintext string
     * @return decrypted plaintext string
     */
    public String decrypt(String ciphertext) {
        if (ciphertext == null || ciphertext.isEmpty()) {
            return ciphertext;
        }

        String trimmed = ciphertext.trim();

        // Check for modern ENC(...) wrapper
        if (isModernEncrypted(trimmed)) {
            return decryptModern(trimmed);
        }

        // Check for legacy format
        if (isLegacyEncrypted(trimmed)) {
            return decryptLegacy(trimmed);
        }

        // Not encrypted, return as is
        return ciphertext;
    }

    /**
     * Checks if a value is encrypted (either modern ENC or legacy format).
     *
     * @param value candidate string
     * @return true if encrypted
     */
    public boolean isEncrypted(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        String trimmed = value.trim();
        return isModernEncrypted(trimmed) || isLegacyEncrypted(trimmed);
    }

    private boolean isModernEncrypted(String value) {
        return value.startsWith(PREFIX_ENC) && value.endsWith(SUFFIX_ENC) && value.length() > (PREFIX_ENC.length() + SUFFIX_ENC.length());
    }

    private boolean isLegacyEncrypted(String value) {
        return value.endsWith(LEGACY_HEX_IDENTIFIER) || value.endsWith(LEGACY_ENCRYPTION_IDENTIFIER);
    }

    private String decryptModern(String trimmed) {
        String content = trimmed.substring(PREFIX_ENC.length(), trimmed.length() - SUFFIX_ENC.length()).trim();
        String base64Payload = content;
        String keyAlias = null;

        int colonIdx = content.indexOf(':');
        if (colonIdx > 0) {
            String prefixPart = content.substring(0, colonIdx).trim();
            if (prefixPart.toLowerCase().startsWith("key-alias=")) {
                keyAlias = prefixPart.substring("key-alias=".length()).trim();
            } else if (prefixPart.toLowerCase().startsWith("alias=")) {
                keyAlias = prefixPart.substring("alias=".length()).trim();
            } else {
                keyAlias = prefixPart;
            }
            base64Payload = content.substring(colonIdx + 1).trim();
        }

        String secret = resolveSecretKeyString(keyAlias);
        SecretKey secretKey = getOrCreateGcmSecretKey(secret);

        try {
            byte[] payload = Base64.getDecoder().decode(base64Payload);
            if (payload.length < GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
                throw new IllegalArgumentException("Payload too short to contain IV and authentication tag");
            }

            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            System.arraycopy(payload, 0, iv, 0, GCM_IV_LENGTH_BYTES);

            int ciphertextLen = payload.length - GCM_IV_LENGTH_BYTES;
            byte[] ciphertextWithTag = new byte[ciphertextLen];
            System.arraycopy(payload, GCM_IV_LENGTH_BYTES, ciphertextWithTag, 0, ciphertextLen);

            Cipher cipher = Cipher.getInstance(ALGORITHM_AES_GCM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            byte[] decrypted = cipher.doFinal(ciphertextWithTag);
            String result = new String(decrypted, StandardCharsets.UTF_8);
            Arrays.fill(decrypted, (byte) 0); // Zero out decrypted sensitive buffer
            return result;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Modern GCM decryption failed: " + e.getMessage(), e);
            throw new RuntimeException("Decryption failed. Please verify the encryption key.", e);
        }
    }

    /**
     * Decrypts legacy format (Hex-encoded Base64 AES-CBC with @##$$$&&&& marker).
     */
    public String decryptLegacy(String msg) {
        if (msg == null || msg.isEmpty()) {
            return msg;
        }

        String candidate = msg.trim();
        try {
            if (candidate.endsWith(LEGACY_HEX_IDENTIFIER)) {
                candidate = safeHexToString(candidate);
            }

            if (candidate.endsWith(LEGACY_ENCRYPTION_IDENTIFIER)) {
                candidate = candidate.substring(0, candidate.length() - LEGACY_ENCRYPTION_IDENTIFIER.length());
            } else {
                return msg;
            }

            String secret = resolveSecretKeyString();
            SecretKey secretKey = getOrCreateLegacyCbcSecretKey(secret);

            Cipher cipher = Cipher.getInstance(ALGORITHM_AES_CBC_LEGACY);
            IvParameterSpec ivSpec = new IvParameterSpec(DEFAULT_DEV_IV.getBytes(StandardCharsets.UTF_8));
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            byte[] decoded = Base64.getDecoder().decode(candidate);
            byte[] decrypted = cipher.doFinal(decoded);
            String result = new String(decrypted, StandardCharsets.UTF_8);
            Arrays.fill(decrypted, (byte) 0); // Zero out decrypted sensitive buffer
            return result;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Legacy decryption failed: " + e.getMessage(), e);
            throw new RuntimeException("Legacy decryption failed: invalid key or corrupted ciphertext", e);
        }
    }

    /**
     * Encrypts in legacy format (for backward compatibility when requested).
     */
    public String encryptLegacy(String msg) {
        if (msg == null || msg.isEmpty()) {
            throw new IllegalArgumentException("Cannot encrypt null or empty string");
        }

        String secret = resolveSecretKeyString();
        SecretKey secretKey = getOrCreateLegacyCbcSecretKey(secret);

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_AES_CBC_LEGACY);
            IvParameterSpec ivSpec = new IvParameterSpec(DEFAULT_DEV_IV.getBytes(StandardCharsets.UTF_8));
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            byte[] encrypted = cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8));
            String base64WithMarker = Base64.getEncoder().encodeToString(encrypted) + LEGACY_ENCRYPTION_IDENTIFIER;
            Arrays.fill(encrypted, (byte) 0);
            return safeStringToHex(base64WithMarker);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Legacy encryption failed: " + e.getMessage(), e);
            throw new RuntimeException("Legacy encryption failed", e);
        }
    }

    private String resolveSecretKeyString() {
        return resolveSecretKeyString(null);
    }

    private String resolveSecretKeyString(String keyAlias) {
        String key = (keyAlias != null && !keyAlias.trim().isEmpty())
                ? keyProvider.getKey(keyAlias.trim())
                : keyProvider.getKey();
        if (key == null || key.trim().isEmpty()) {
            key = DEFAULT_DEV_KEY;
        }
        return key.trim();
    }

    /**
     * Derives a 256-bit AES key using PBKDF2WithHmacSHA256, caching the result.
     */
    public static SecretKey getOrCreateGcmSecretKey(String passphrase) {
        if (GCM_KEY_CACHE.size() > MAX_KEY_CACHE_SIZE) {
            GCM_KEY_CACHE.clear();
        }
        return GCM_KEY_CACHE.computeIfAbsent(passphrase, pass -> {
            try {
                // If the key is already a 64-character hex string (32 bytes = 256 bits), parse directly
                if (pass.length() == 64 && pass.matches("^[0-9a-fA-F]+$")) {
                    byte[] raw = new byte[32];
                    for (int i = 0; i < 32; i++) {
                        raw[i] = (byte) Integer.parseInt(pass.substring(i * 2, i * 2 + 2), 16);
                    }
                    SecretKey key = new SecretKeySpec(raw, "AES");
                    Arrays.fill(raw, (byte) 0);
                    return key;
                }

                // Standard PBKDF2 derivation with 600,000 iterations (OWASP recommendation)
                SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_PBKDF2);
                KeySpec spec = new PBEKeySpec(pass.toCharArray(), KDF_SALT, PBKDF2_ITERATIONS, AES_KEY_LENGTH_BITS);
                byte[] keyBytes = factory.generateSecret(spec).getEncoded();
                SecretKey key = new SecretKeySpec(keyBytes, "AES");
                Arrays.fill(keyBytes, (byte) 0);
                return key;
            } catch (Exception e) {
                // Fallback to SHA-256 digest if PBKDF2 is unavailable on legacy runtimes
                try {
                    MessageDigest digest = MessageDigest.getInstance(HASH_ALGO_SHA256);
                    byte[] keyBytes = digest.digest(pass.getBytes(StandardCharsets.UTF_8));
                    SecretKey key = new SecretKeySpec(keyBytes, "AES");
                    Arrays.fill(keyBytes, (byte) 0);
                    return key;
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException("Failed to derive AES-256 key", ex);
                }
            }
        });
    }

    /**
     * Derives key using the legacy algorithm (SHA-512 Base64 32-char slice) for backward compatibility.
     */
    public static SecretKey getOrCreateLegacyCbcSecretKey(String passphrase) {
        if (CBC_KEY_CACHE.size() > MAX_KEY_CACHE_SIZE) {
            CBC_KEY_CACHE.clear();
        }
        return CBC_KEY_CACHE.computeIfAbsent(passphrase, pass -> {
            try {
                MessageDigest digester = MessageDigest.getInstance(HASH_ALGO_SHA512);
                int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
                char[] keySalt = (pass.length() > maxKeyLen && maxKeyLen > 0)
                        ? pass.substring(0, maxKeyLen).toCharArray()
                        : pass.toCharArray();

                for (char word : keySalt) {
                    digester.update((byte) word);
                }
                String encode = Base64.getEncoder().encodeToString(digester.digest());
                byte[] key = (encode.length() > 32)
                        ? Base64.getDecoder().decode(encode.substring(0, 32))
                        : Base64.getDecoder().decode(encode);
                SecretKey secretKey = new SecretKeySpec(key, "AES");
                Arrays.fill(key, (byte) 0);
                return secretKey;
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException("Failed to derive legacy secret key", ex);
            }
        });
    }

    /**
     * Fast, allocation-free string-to-hex conversion (2 digits per byte, UTF-8 safe).
     */
    public static String safeStringToHex(String str) {
        if (str == null) return null;
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString().toUpperCase();
    }

    /**
     * Fast, allocation-free hex-to-string conversion with strict non-hex validation (UTF-8 safe).
     */
    public static String safeHexToString(String hex) {
        if (hex == null || hex.isEmpty()) return hex;
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            int h = Character.digit(hex.charAt(i), 16);
            int l = Character.digit(hex.charAt(i + 1), 16);
            if (h == -1 || l == -1) {
                throw new IllegalArgumentException("Invalid hex character at index " + i);
            }
            bytes[i / 2] = (byte) ((h << 4) + l);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
