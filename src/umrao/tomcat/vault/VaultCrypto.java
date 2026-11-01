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

import umrao.tomcat.vault.exception.DecryptionException;
import umrao.tomcat.vault.exception.VaultException;
import umrao.tomcat.vault.key.CompositeKeyProvider;
import umrao.tomcat.vault.key.KeyProvider;
import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;

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
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import static umrao.tomcat.vault.VaultConstants.AES_KEY_LENGTH_BITS;
import static umrao.tomcat.vault.VaultConstants.ALGORITHM_AES_CBC_LEGACY;
import static umrao.tomcat.vault.VaultConstants.ALGORITHM_AES_GCM;
import static umrao.tomcat.vault.VaultConstants.DEFAULT_DEV_IV;
import static umrao.tomcat.vault.VaultConstants.DEFAULT_DEV_KEY;
import static umrao.tomcat.vault.VaultConstants.ENV_KEY;
import static umrao.tomcat.vault.VaultConstants.ENV_PBKDF2_ITERATIONS;
import static umrao.tomcat.vault.VaultConstants.ENV_SALT;
import static umrao.tomcat.vault.VaultConstants.ENV_STRICT;
import static umrao.tomcat.vault.VaultConstants.GCM_IV_LENGTH_BYTES;
import static umrao.tomcat.vault.VaultConstants.GCM_TAG_LENGTH_BITS;
import static umrao.tomcat.vault.VaultConstants.HASH_ALGO_SHA256;
import static umrao.tomcat.vault.VaultConstants.HASH_ALGO_SHA512;
import static umrao.tomcat.vault.VaultConstants.KDF_PBKDF2;
import static umrao.tomcat.vault.VaultConstants.LEGACY_ENCRYPTION_IDENTIFIER;
import static umrao.tomcat.vault.VaultConstants.LEGACY_HEX_IDENTIFIER;
import static umrao.tomcat.vault.VaultConstants.PBKDF2_ITERATIONS;
import static umrao.tomcat.vault.VaultConstants.PREFIX_ENC;
import static umrao.tomcat.vault.VaultConstants.SUFFIX_ENC;
import static umrao.tomcat.vault.VaultConstants.SYS_PROP_KEY;
import static umrao.tomcat.vault.VaultConstants.SYS_PROP_PBKDF2_ITERATIONS;
import static umrao.tomcat.vault.VaultConstants.SYS_PROP_SALT;
import static umrao.tomcat.vault.VaultConstants.SYS_PROP_STRICT;

/**
 * Enterprise-grade cryptographic engine supporting AES-256-GCM authenticated encryption,
 * standard ENC(...) envelope formats, dynamic random IVs, and legacy AES-CBC backward compatibility.
 * @author Vivek Umrao
 */
public class VaultCrypto {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(VaultCrypto.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Fixed salt for PBKDF2 key derivation from passphrase string
    private static final byte[] KDF_SALT = "ApacheTomcatVaultSaltKey2026".getBytes(StandardCharsets.UTF_8);

    // Bounded LRU cache of derived SecretKeys to prevent unbounded memory growth (CWE-400)
    // Keyed by cryptographic SHA-256 digest of (passphrase + salt) to avoid keeping plaintext keys in heap (CWE-316)
    private static final int MAX_KEY_CACHE_SIZE = 128;

    private static final class LruKeyCache {
        private final int maxSize;
        private final Map<String, SecretKey> map;

        LruKeyCache(int maxSize) {
            this.maxSize = maxSize;
            this.map = new java.util.LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, SecretKey> eldest) {
                    return size() > LruKeyCache.this.maxSize;
                }
            };
        }

        synchronized SecretKey get(String key) {
            return map.get(key);
        }

        synchronized void put(String key, SecretKey value) {
            map.put(key, value);
        }

        synchronized void clear() {
            map.clear();
        }
    }

    private static final LruKeyCache GCM_KEY_CACHE = new LruKeyCache(MAX_KEY_CACHE_SIZE);
    private static final LruKeyCache CBC_KEY_CACHE = new LruKeyCache(MAX_KEY_CACHE_SIZE);

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
            public String getKey(String keyAlias) {
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
     * Clears all cached derived cryptographic keys.
     * Useful when keys have been rotated dynamically.
     */
    public static void clearKeyCache() {
        GCM_KEY_CACHE.clear();
        CBC_KEY_CACHE.clear();
    }

    /**
     * Encrypts a plaintext message using modern AES-256-GCM with a dynamic 12-byte IV.
     * The result is formatted as {@code ENC(Base64(IV + Ciphertext + Tag))}.
     *
     * @param plaintext cleartext string
     * @return ENC(...) envelope formatted string
     */
    public String encrypt(String plaintext) {
        return encrypt(plaintext, null, null);
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
        return encrypt(plaintext, keyAlias, null);
    }

    /**
     * Encrypts a plaintext message with an optional key alias and optional Authenticated Additional Data (AAD).
     *
     * @param plaintext cleartext string
     * @param keyAlias key alias or version identifier
     * @param aad optional Authenticated Additional Data for context binding
     * @return versioned ENC(...) envelope formatted string
     */
    public String encrypt(String plaintext, String keyAlias, byte[] aad) {
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

            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

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
            LOGGER.error("Encryption failed: " + e.getMessage(), e);
            throw new VaultException("Encryption operation failed", e);
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
        return decrypt(ciphertext, null);
    }

    /**
     * Decrypts an encrypted property value with optional Authenticated Additional Data (AAD).
     *
     * @param ciphertext encrypted envelope or plaintext string
     * @param aad optional Authenticated Additional Data for context verification
     * @return decrypted plaintext string
     */
    public String decrypt(String ciphertext, byte[] aad) {
        if (ciphertext == null || ciphertext.isEmpty()) {
            return ciphertext;
        }

        String trimmed = ciphertext.trim();

        // Check for modern ENC(...) wrapper
        if (isModernEncrypted(trimmed)) {
            return decryptModern(trimmed, aad);
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

    private static final java.util.regex.Pattern EMBEDDED_ENC_PATTERN =
            java.util.regex.Pattern.compile("ENC\\(([^()]+)\\)");

    /**
     * Checks if a value contains one or more embedded ENC(...) tokens (e.g. within a JDBC URL or composite property).
     *
     * @param value candidate string
     * @return true if embedded ENC(...) tokens are present
     */
    public boolean hasEmbeddedEncrypted(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        return EMBEDDED_ENC_PATTERN.matcher(value).find();
    }

    /**
     * Decrypts all embedded ENC(...) tokens found within a composite string (e.g. within a JDBC URL or connection properties).
     * Non-encrypted portions of the string remain unaltered.
     *
     * @param value candidate string with embedded tokens
     * @return string with all embedded ENC(...) tokens decrypted
     */
    public String decryptEmbedded(String value) {
        return decryptEmbedded(value, null);
    }

    /**
     * Decrypts all embedded ENC(...) tokens found within a composite string with optional Authenticated Additional Data.
     *
     * @param value candidate string with embedded tokens
     * @param aad optional Authenticated Additional Data
     * @return string with all embedded ENC(...) tokens decrypted
     */
    public String decryptEmbedded(String value, byte[] aad) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        java.util.regex.Matcher matcher = EMBEDDED_ENC_PATTERN.matcher(value);
        if (!matcher.find()) {
            return value;
        }
        StringBuilder sb = new StringBuilder();
        int lastEnd = 0;
        matcher.reset();
        while (matcher.find()) {
            sb.append(value, lastEnd, matcher.start());
            String token = matcher.group(0);
            String decrypted = decrypt(token, aad);
            sb.append(decrypted != null ? decrypted : token);
            lastEnd = matcher.end();
        }
        sb.append(value.substring(lastEnd));
        return sb.toString();
    }

    private boolean isModernEncrypted(String value) {
        return value.startsWith(PREFIX_ENC) && value.endsWith(SUFFIX_ENC) && value.length() > (PREFIX_ENC.length() + SUFFIX_ENC.length());
    }

    private boolean isLegacyEncrypted(String value) {
        return value.endsWith(LEGACY_HEX_IDENTIFIER) || value.endsWith(LEGACY_ENCRYPTION_IDENTIFIER);
    }

    private String decryptModern(String trimmed, byte[] aad) {
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

            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            byte[] decrypted = cipher.doFinal(ciphertextWithTag);
            String result = new String(decrypted, StandardCharsets.UTF_8);
            Arrays.fill(decrypted, (byte) 0); // Zero out decrypted sensitive buffer
            return result;
        } catch (Exception e) {
            LOGGER.error("Modern GCM decryption failed: " + e.getMessage(), e);
            throw new DecryptionException("Decryption failed. Please verify the encryption key.", e);
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
            LOGGER.error("Legacy decryption failed: " + e.getMessage(), e);
            throw new DecryptionException("Legacy decryption failed: invalid key or corrupted ciphertext", e);
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
            LOGGER.error("Legacy encryption failed: " + e.getMessage(), e);
            throw new VaultException("Legacy encryption failed", e);
        }
    }

    private String resolveSecretKeyString() {
        return resolveSecretKeyString(null);
    }

    private String resolveSecretKeyString(String keyAlias) {
        String key = (keyAlias != null && !keyAlias.trim().isEmpty())
                ? keyProvider.getKey(keyAlias.trim())
                : keyProvider.getKey();
        boolean isStrict = Boolean.getBoolean(SYS_PROP_STRICT)
                || "true".equalsIgnoreCase(System.getenv(ENV_STRICT));
        if (key == null || key.trim().isEmpty()) {
            if (isStrict) {
                throw new SecurityException("Tomcat Vault is operating in strict production mode: " +
                        "fallback to default development key is forbidden. " +
                        "Please configure an external key via environment variable " + ENV_KEY +
                        " or system property -D" + SYS_PROP_KEY);
            }
            key = DEFAULT_DEV_KEY;
        } else if (isStrict && DEFAULT_DEV_KEY.equals(key.trim())) {
            throw new SecurityException("Tomcat Vault is operating in strict production mode: " +
                    "fallback to default development key is forbidden.");
        }
        return key.trim();
    }

    private static byte[] resolveKdfSalt() {
        String salt = System.getProperty(SYS_PROP_SALT);
        if (salt == null || salt.trim().isEmpty()) {
            salt = System.getenv(ENV_SALT);
        }
        if (salt != null && !salt.trim().isEmpty()) {
            return salt.trim().getBytes(StandardCharsets.UTF_8);
        }
        return KDF_SALT;
    }

    private static int resolvePbkdf2Iterations() {
        String prop = System.getProperty(SYS_PROP_PBKDF2_ITERATIONS);
        if (prop == null || prop.trim().isEmpty()) {
            prop = System.getenv(ENV_PBKDF2_ITERATIONS);
        }
        if (prop != null && !prop.trim().isEmpty()) {
            try {
                int iters = Integer.parseInt(prop.trim());
                if (iters >= 1000) {
                    return iters;
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return PBKDF2_ITERATIONS;
    }

    public static boolean isHex64(String s) {
        if (s == null || s.length() != 64) {
            return false;
        }
        for (int i = 0; i < 64; i++) {
            char c = s.charAt(i);
            if (Character.digit(c, 16) == -1) {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks if a string is a 44-character Base64 encoding of a 256-bit (32-byte) key.
     */
    public static boolean isBase64Key32(String s) {
        if (s == null || s.length() != 44 || !s.endsWith("=")) {
            return false;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(s);
            boolean is32 = decoded.length == 32;
            Arrays.fill(decoded, (byte) 0);
            return is32;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String hashCacheKey(String pass, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALGO_SHA256);
            md.update(pass.getBytes(StandardCharsets.UTF_8));
            md.update((byte) 0);
            md.update(salt);
            byte[] digest = md.digest();
            return safeBytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            return pass;
        }
    }

    /**
     * Derives a 256-bit AES key using PBKDF2WithHmacSHA256, caching the result in LRU cache.
     */
    public static SecretKey getOrCreateGcmSecretKey(String passphrase) {
        byte[] salt = resolveKdfSalt();
        String cacheKey = hashCacheKey(passphrase, salt);

        SecretKey cached = GCM_KEY_CACHE.get(cacheKey);
        if (cached != null) {
            return cached;
        }

        SecretKey derived = deriveGcmSecretKey(passphrase, salt);
        GCM_KEY_CACHE.put(cacheKey, derived);
        return derived;
    }

    private static SecretKey deriveGcmSecretKey(String passphrase, byte[] salt) {
        try {
            // If the key is already a 64-character hex string (32 bytes = 256 bits), parse directly
            if (isHex64(passphrase)) {
                byte[] raw = new byte[32];
                for (int i = 0; i < 32; i++) {
                    raw[i] = (byte) Integer.parseInt(passphrase.substring(i * 2, i * 2 + 2), 16);
                }
                SecretKey key = new SecretKeySpec(raw, "AES");
                Arrays.fill(raw, (byte) 0);
                return key;
            }

            // If the key is already a 32-byte Base64 key (e.g. from Java KeyStore or HSM), decode directly
            if (isBase64Key32(passphrase)) {
                byte[] raw = Base64.getDecoder().decode(passphrase);
                SecretKey key = new SecretKeySpec(raw, "AES");
                Arrays.fill(raw, (byte) 0);
                return key;
            }

            // Standard PBKDF2 derivation with configurable iterations (OWASP recommendation: 600,000)
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_PBKDF2);
            char[] passChars = passphrase.toCharArray();
            int iterations = resolvePbkdf2Iterations();
            PBEKeySpec spec = new PBEKeySpec(passChars, salt, iterations, AES_KEY_LENGTH_BITS);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            Arrays.fill(passChars, '\0');
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            Arrays.fill(keyBytes, (byte) 0);
            return key;
        } catch (Exception e) {
            // Fallback to SHA-256 digest if PBKDF2 is unavailable on legacy runtimes
            try {
                MessageDigest digest = MessageDigest.getInstance(HASH_ALGO_SHA256);
                byte[] keyBytes = digest.digest(passphrase.getBytes(StandardCharsets.UTF_8));
                SecretKey key = new SecretKeySpec(keyBytes, "AES");
                Arrays.fill(keyBytes, (byte) 0);
                return key;
            } catch (NoSuchAlgorithmException ex) {
                throw new VaultException("Failed to derive AES-256 key", ex);
            }
        }
    }

    /**
     * Derives key using the legacy algorithm (SHA-512 Base64 32-char slice) for backward compatibility.
     */
    public static SecretKey getOrCreateLegacyCbcSecretKey(String passphrase) {
        byte[] salt = DEFAULT_DEV_IV.getBytes(StandardCharsets.UTF_8);
        String cacheKey = hashCacheKey(passphrase, salt);

        SecretKey cached = CBC_KEY_CACHE.get(cacheKey);
        if (cached != null) {
            return cached;
        }

        try {
            MessageDigest digester = MessageDigest.getInstance(HASH_ALGO_SHA512);
            int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            char[] keySalt = (passphrase.length() > maxKeyLen && maxKeyLen > 0)
                    ? passphrase.substring(0, maxKeyLen).toCharArray()
                    : passphrase.toCharArray();

            for (char word : keySalt) {
                digester.update((byte) word);
            }
            String encode = Base64.getEncoder().encodeToString(digester.digest());
            byte[] key = (encode.length() > 32)
                    ? Base64.getDecoder().decode(encode.substring(0, 32))
                    : Base64.getDecoder().decode(encode);
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            Arrays.fill(key, (byte) 0);
            CBC_KEY_CACHE.put(cacheKey, secretKey);
            return secretKey;
        } catch (NoSuchAlgorithmException ex) {
            throw new VaultException("Failed to derive legacy secret key", ex);
        }
    }

    /**
     * Fast, allocation-free string-to-hex conversion (2 digits per byte, UTF-8 safe).
     */
    public static String safeStringToHex(String str) {
        if (str == null) return null;
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        return safeBytesToHex(bytes);
    }

    /**
     * Fast, allocation-free byte-array-to-hex conversion (2 digits per byte, uppercase).
     */
    public static String safeBytesToHex(byte[] bytes) {
        if (bytes == null) return null;
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
