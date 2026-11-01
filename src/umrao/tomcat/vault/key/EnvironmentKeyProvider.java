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

package umrao.tomcat.vault.key;

import umrao.tomcat.vault.VaultConstants;

import java.util.function.Function;

/**
 * Resolves the encryption key from OS environment variables.
 * Checks {@code TOMCAT_VAULT_KEY} and falls back to {@code TOMCAT_ENCRYPTION_KEY}.
 * @author Vivek Umrao
 */
public class EnvironmentKeyProvider implements KeyProvider {

    private final String customEnvVar;
    private final Function<String, String> envResolver;

    public EnvironmentKeyProvider() {
        this(null, System::getenv);
    }

    public EnvironmentKeyProvider(String customEnvVar) {
        this(customEnvVar, System::getenv);
    }

    public EnvironmentKeyProvider(String customEnvVar, Function<String, String> envResolver) {
        this.customEnvVar = customEnvVar;
        this.envResolver = envResolver != null ? envResolver : System::getenv;
    }

    @Override
    public String getKey() {
        if (customEnvVar != null && !customEnvVar.trim().isEmpty()) {
            String val = envResolver.apply(customEnvVar.trim());
            if (val != null && !val.trim().isEmpty()) {
                return val.trim();
            }
        }

        String primary = envResolver.apply(VaultConstants.ENV_KEY);
        if (primary != null && !primary.trim().isEmpty()) {
            return primary.trim();
        }

        String alternate = envResolver.apply(VaultConstants.ENV_KEY_ALT);
        if (alternate != null && !alternate.trim().isEmpty()) {
            return alternate.trim();
        }

        return null;
    }

    @Override
    public String getKey(String keyAlias) {
        if (keyAlias == null || keyAlias.trim().isEmpty()) {
            return getKey();
        }
        String sanitizedAlias = keyAlias.trim().replace('-', '_').replace('.', '_').toUpperCase();
        
        if (customEnvVar != null && !customEnvVar.trim().isEmpty()) {
            String val = envResolver.apply(customEnvVar.trim() + "_" + sanitizedAlias);
            if (val != null && !val.trim().isEmpty()) {
                return val.trim();
            }
        }

        String versionedKey = envResolver.apply(VaultConstants.ENV_KEY + "_" + sanitizedAlias);
        if (versionedKey != null && !versionedKey.trim().isEmpty()) {
            return versionedKey.trim();
        }

        String altVersionedKey = envResolver.apply(VaultConstants.ENV_KEY_ALT + "_" + sanitizedAlias);
        if (altVersionedKey != null && !altVersionedKey.trim().isEmpty()) {
            return altVersionedKey.trim();
        }

        return getKey();
    }

    @Override
    public String getProviderName() {
        return "EnvironmentKeyProvider" + (customEnvVar != null ? "[" + customEnvVar + "]" : "");
    }
}
