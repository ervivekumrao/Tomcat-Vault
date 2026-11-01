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

import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;
import umrao.tomcat.vault.secret.SecretResolverRegistry;

/**
 * Cloud-native key provider that resolves master encryption keys directly
 * from external secret management systems (such as AWS Secrets Manager,
 * HashiCorp Vault, Azure Key Vault, or GCP Secret Manager) via {@link SecretResolverRegistry}.
 *
 * @author Vivek Umrao
 */
@SuppressWarnings("unused")
public class SecretResolverKeyProvider implements CloudVaultKeyProvider {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(SecretResolverKeyProvider.class);

    public static final String SYS_PROP_CLOUD_PATH = "tomcat.vault.cloud.path";
    public static final String ENV_CLOUD_PATH = "TOMCAT_VAULT_CLOUD_PATH";

    private final String vaultSecretPath;
    private final SecretResolverRegistry registry;

    public SecretResolverKeyProvider() {
        this(resolveConfiguredPath(), SecretResolverRegistry.getInstance());
    }

    public SecretResolverKeyProvider(String vaultSecretPath) {
        this(vaultSecretPath, SecretResolverRegistry.getInstance());
    }

    public SecretResolverKeyProvider(String vaultSecretPath, SecretResolverRegistry registry) {
        this.vaultSecretPath = vaultSecretPath != null ? vaultSecretPath.trim() : null;
        this.registry = registry != null ? registry : SecretResolverRegistry.getInstance();
    }

    private static String resolveConfiguredPath() {
        String path = System.getProperty(SYS_PROP_CLOUD_PATH);
        if (path == null || path.trim().isEmpty()) {
            path = System.getenv(ENV_CLOUD_PATH);
        }
        return (path != null && !path.trim().isEmpty()) ? path.trim() : null;
    }

    @Override
    public String getKey() {
        if (vaultSecretPath == null || vaultSecretPath.isEmpty()) {
            return null;
        }
        try {
            if (registry.isResolvable(vaultSecretPath)) {
                String resolved = registry.resolve(vaultSecretPath);
                if (resolved != null && !resolved.trim().isEmpty() && !resolved.equals(vaultSecretPath)) {
                    LOGGER.debug("Resolved encryption key from cloud vault path: " + vaultSecretPath);
                    return resolved.trim();
                }
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to resolve key from cloud vault path [" + vaultSecretPath + "]: " + e.getMessage(), e);
        }
        return null;
    }

    @Override
    public String getKey(String keyAlias) {
        if (keyAlias != null && !keyAlias.trim().isEmpty() && vaultSecretPath != null) {
            // Check if alias-specific path exists e.g. path with alias appended
            String aliasPath = vaultSecretPath.contains("#")
                    ? vaultSecretPath.substring(0, vaultSecretPath.indexOf('#')) + "#" + keyAlias.trim()
                    : vaultSecretPath + "_" + keyAlias.trim();
            if (registry.isResolvable(aliasPath)) {
                try {
                    String resolved = registry.resolve(aliasPath);
                    if (resolved != null && !resolved.trim().isEmpty() && !resolved.equals(aliasPath)) {
                        return resolved.trim();
                    }
                } catch (Exception ignored) {
                }
            }
        }
        return getKey();
    }

    @Override
    public String getVaultSecretPath() {
        return vaultSecretPath;
    }

    @Override
    public boolean isAvailable() {
        return vaultSecretPath != null && registry.isResolvable(vaultSecretPath);
    }

    @Override
    public String getProviderName() {
        return "SecretResolverKeyProvider[" + (vaultSecretPath != null ? vaultSecretPath : "unconfigured") + "]";
    }
}
