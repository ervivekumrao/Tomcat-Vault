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

/**
 * Constants and configuration keys for Tomcat Vault.
 */
@SuppressWarnings("unused")
public final class VaultConstants {

    // Default algorithms
    public static final String ALGORITHM_AES_GCM = "AES/GCM/NoPadding";
    public static final String ALGORITHM_AES_CBC_LEGACY = "AES/CBC/PKCS5Padding";
    public static final String HASH_ALGO_SHA256 = "SHA-256";
    public static final String HASH_ALGO_SHA512 = "SHA-512";
    public static final String KDF_PBKDF2 = "PBKDF2WithHmacSHA256";

    // Cryptographic parameters
    public static final int GCM_IV_LENGTH_BYTES = 12; // 96-bit IV recommended by NIST SP 800-38D
    public static final int GCM_TAG_LENGTH_BITS = 128; // 128-bit authentication tag
    public static final int AES_KEY_LENGTH_BITS = 256;
    public static final int PBKDF2_ITERATIONS = 600000; // OWASP recommendation for PBKDF2

    // Prefixes and markers
    public static final String PREFIX_ENC = "ENC(";
    public static final String SUFFIX_ENC = ")";
    public static final String LEGACY_ENCRYPTION_IDENTIFIER = "@##$$$&&&&";
    public static final String LEGACY_HEX_IDENTIFIER = "40232324242426262626";

    // System Property & Environment Variable Keys
    public static final String ENV_KEY = "TOMCAT_VAULT_KEY";
    public static final String ENV_KEY_ALT = "TOMCAT_ENCRYPTION_KEY";
    public static final String ENV_KEYFILE = "TOMCAT_VAULT_KEYFILE";
    public static final String SYS_PROP_KEY = "tomcat.vault.key";
    public static final String SYS_PROP_KEY_ALT = "tomcat.encryption.key";
    public static final String SYS_PROP_KEYFILE = "tomcat.vault.keyfile";
    public static final String SYS_PROP_KEYSTORE = "tomcat.vault.keystore";
    public static final String SYS_PROP_KEYSTORE_PASSWORD = "tomcat.vault.keystore.password";
    public static final String SYS_PROP_KEYSTORE_TYPE = "tomcat.vault.keystore.type";
    public static final String SYS_PROP_KEYSTORE_ALIAS = "tomcat.vault.keystore.alias";
    public static final String SYS_PROP_SALT = "tomcat.vault.salt";
    public static final String ENV_KEYSTORE = "TOMCAT_VAULT_KEYSTORE";
    public static final String ENV_KEYSTORE_PASSWORD = "TOMCAT_VAULT_KEYSTORE_PASSWORD";
    public static final String ENV_KEYSTORE_ALIAS = "TOMCAT_VAULT_KEYSTORE_ALIAS";
    public static final String ENV_SALT = "TOMCAT_VAULT_SALT";

    // Logging & Debugging Properties
    public static final String SYS_PROP_LOG_FILE = "tomcat.vault.log.file";
    public static final String SYS_PROP_LOG_DEBUG = "tomcat.vault.debug";
    public static final String SYS_PROP_LOG_LEVEL = "tomcat.vault.log.level";
    public static final String ENV_LOG_FILE = "TOMCAT_VAULT_LOG_FILE";

    // Strict Production Mode & Tuning Properties
    public static final String SYS_PROP_STRICT = "tomcat.vault.strict";
    public static final String ENV_STRICT = "TOMCAT_VAULT_STRICT";
    public static final String SYS_PROP_PBKDF2_ITERATIONS = "tomcat.vault.pbkdf2.iterations";
    public static final String ENV_PBKDF2_ITERATIONS = "TOMCAT_VAULT_PBKDF2_ITERATIONS";

    // Fallback default key (used only if no external key provider is configured)
    public static final String DEFAULT_DEV_KEY = "V5HBYXPGOTRLDYZ9SFENGA8KUYJNM6AKE5RLKMSOYELQSKIBVWLZHUAMZFQKQ2QM";
    public static final String DEFAULT_DEV_IV = "YMW1JOTRQN4BDHQ0";

    private VaultConstants() {
        // Prevent instantiation
    }
}
