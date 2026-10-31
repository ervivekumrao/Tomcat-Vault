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

package org.apache.tomcat.vault.key;

import org.apache.tomcat.vault.VaultConstants;

/**
 * Resolves the encryption key from Java System Properties (e.g. passed via -D in CATALINA_OPTS).
 * Checks {@code tomcat.vault.key} and falls back to {@code tomcat.encryption.key}.
 */
public class SystemPropertyKeyProvider implements KeyProvider {

    private final String customProperty;

    public SystemPropertyKeyProvider() {
        this(null);
    }

    public SystemPropertyKeyProvider(String customProperty) {
        this.customProperty = customProperty;
    }

    @Override
    public String getKey() {
        if (customProperty != null && !customProperty.trim().isEmpty()) {
            String val = System.getProperty(customProperty.trim());
            if (val != null && !val.trim().isEmpty()) {
                return val.trim();
            }
        }

        String primary = System.getProperty(VaultConstants.SYS_PROP_KEY);
        if (primary != null && !primary.trim().isEmpty()) {
            return primary.trim();
        }

        String alternate = System.getProperty(VaultConstants.SYS_PROP_KEY_ALT);
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
        String cleanAlias = keyAlias.trim();

        if (customProperty != null && !customProperty.trim().isEmpty()) {
            String val = System.getProperty(customProperty.trim() + "." + cleanAlias);
            if (val != null && !val.trim().isEmpty()) {
                return val.trim();
            }
        }

        String versionedKey = System.getProperty(VaultConstants.SYS_PROP_KEY + "." + cleanAlias);
        if (versionedKey != null && !versionedKey.trim().isEmpty()) {
            return versionedKey.trim();
        }

        String altVersionedKey = System.getProperty(VaultConstants.SYS_PROP_KEY_ALT + "." + cleanAlias);
        if (altVersionedKey != null && !altVersionedKey.trim().isEmpty()) {
            return altVersionedKey.trim();
        }

        return getKey();
    }

    @Override
    public String getProviderName() {
        return "SystemPropertyKeyProvider" + (customProperty != null ? "[" + customProperty + "]" : "");
    }
}
