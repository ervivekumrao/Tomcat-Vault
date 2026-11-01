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

package umrao.tomcat.vault.key;

/**
 * Strategy interface for resolving encryption/decryption keys.
 * Supports external key management from environment variables, system properties,
 * key files, and enterprise secret vaults.
 */
@SuppressWarnings("unused")
public interface KeyProvider {

    /**
     * Resolves and returns the default cryptographic key or passphrase.
     *
     * @return the secret key string, or null if this provider cannot resolve a key
     */
    String getKey();

    /**
     * Resolves and returns a cryptographic key for a specific key alias or version.
     *
     * @param keyAlias key alias or version identifier (e.g. "v1", "v2", "prod-key")
     * @return the secret key string, or null if not found
     */
    default String getKey(String keyAlias) {
        return (keyAlias == null || keyAlias.isEmpty()) ? getKey() : null;
    }

    /**
     * Checks if this provider can resolve a key for the specified alias.
     *
     * @param keyAlias key alias or version identifier
     * @return true if key can be resolved
     */
    default boolean hasKey(String keyAlias) {
        return getKey(keyAlias) != null;
    }

    /**
     * Returns a human-readable identifier for this key provider.
     *
     * @return provider name
     */
    String getProviderName();
}
