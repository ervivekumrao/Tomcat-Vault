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

package umrao.tomcat.vault.secret;

import umrao.tomcat.vault.VaultConstants;
import umrao.tomcat.vault.exception.SecretResolutionException;
import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;

import java.util.List;
import java.util.ServiceLoader;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Central registry for cloud and enterprise {@link SecretResolver} implementations.
 * Enables zero-static-key configuration by resolving secrets directly from AWS Secrets Manager,
 * HashiCorp Vault, Azure Key Vault, and Google Cloud Secret Manager.
 * Supports automatic discovery via Java {@link ServiceLoader} SPI.
 */
@SuppressWarnings("unused")
public class SecretResolverRegistry {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(SecretResolverRegistry.class);
    private static final SecretResolverRegistry INSTANCE = new SecretResolverRegistry();

    private final List<SecretResolver> resolvers = new CopyOnWriteArrayList<>();

    public static SecretResolverRegistry getInstance() {
        return INSTANCE;
    }

    public SecretResolverRegistry() {
        registerDefaultResolvers();
    }

    private void registerDefaultResolvers() {
        // Built-in lightweight cloud secret resolver supporting AWS_SECRET, VAULT, AZURE_VAULT, and GCP_SECRET
        resolvers.add(new StandardCloudSecretResolver());

        // Discover external secret resolvers registered via standard Java ServiceLoader SPI
        try {
            ServiceLoader<SecretResolver> loader = ServiceLoader.load(SecretResolver.class);
            for (SecretResolver resolver : loader) {
                if (resolver != null) {
                    resolvers.add(0, resolver);
                    LOGGER.info("Discovered and registered SPI SecretResolver: " + resolver.getResolverName());
                }
            }
        } catch (Throwable t) {
            LOGGER.debug("ServiceLoader secret resolver discovery skipped: " + t.getMessage());
        }
    }

    public void registerResolver(SecretResolver resolver) {
        if (resolver != null) {
            resolvers.add(0, resolver);
            LOGGER.info("Registered custom SecretResolver: " + resolver.getResolverName());
        }
    }

    public void unregisterResolver(SecretResolver resolver) {
        if (resolver != null) {
            resolvers.remove(resolver);
        }
    }

    public void clearResolvers() {
        resolvers.clear();
    }

    public void resetDefaultResolvers() {
        resolvers.clear();
        registerDefaultResolvers();
    }

    public boolean isResolvable(String value) {
        if (value == null || value.trim().isEmpty()) {
            return false;
        }
        String trimmed = value.trim();
        for (SecretResolver resolver : resolvers) {
            if (resolver.supports(trimmed)) {
                return true;
            }
        }
        return false;
    }

    public String resolve(String expression) {
        if (expression == null || expression.trim().isEmpty()) {
            return expression;
        }
        String trimmed = expression.trim();
        boolean matchedAny = false;

        for (SecretResolver resolver : resolvers) {
            if (resolver.supports(trimmed)) {
                matchedAny = true;
                try {
                    String resolved = resolver.resolve(trimmed);
                    if (resolved != null) {
                        return resolved;
                    }
                } catch (Exception e) {
                    LOGGER.error("Failed to resolve secret expression with " + resolver.getResolverName() + ": " + e.getMessage(), e);
                    throw new SecretResolutionException("Secret resolution failed for: " + trimmed, e);
                }
            }
        }

        boolean isStrict = Boolean.getBoolean(VaultConstants.SYS_PROP_STRICT)
                || "true".equalsIgnoreCase(System.getenv(VaultConstants.ENV_STRICT));
        if (isStrict && matchedAny) {
            throw new SecretResolutionException("Strict mode violation: Cloud secret reference [" + trimmed +
                    "] could not be resolved from environment or properties.");
        }

        return expression;
    }

    /**
     * Built-in standard cloud secret resolver.
     * Evaluates expressions such as:
     * - AWS_SECRET(name#field)
     * - VAULT(path#field)
     * - AZURE_VAULT(secret-name)
     * - GCP_SECRET(secret-name)
     */
    public static class StandardCloudSecretResolver implements SecretResolver {

        @Override
        public boolean supports(String expression) {
            if (expression == null) return false;
            String upper = expression.trim().toUpperCase();
            return (upper.startsWith("AWS_SECRET(") && upper.endsWith(")"))
                    || (upper.startsWith("VAULT(") && upper.endsWith(")"))
                    || (upper.startsWith("AZURE_VAULT(") && upper.endsWith(")"))
                    || (upper.startsWith("GCP_SECRET(") && upper.endsWith(")"));
        }

        @Override
        public String resolve(String expression) {
            String trimmed = expression.trim();
            int openParen = trimmed.indexOf('(');
            int closeParen = trimmed.lastIndexOf(')');
            if (openParen == -1 || closeParen <= openParen) {
                return expression;
            }

            String prefix = trimmed.substring(0, openParen).trim().toUpperCase();
            String inner = trimmed.substring(openParen + 1, closeParen).trim();

            // Try resolving via mapped environment variable or system property
            String sanitized = inner.replace('/', '_').replace('-', '_').replace('.', '_').replace('#', '_').replace(':', '_').toUpperCase();

            // Check system property first, e.g. -Daws.secret.prod_db_password=...
            String sysKey = prefix.toLowerCase().replace('_', '.') + "." + inner.replace('/', '.').replace('#', '.');
            String val = System.getProperty(sysKey);
            if (val != null && !val.trim().isEmpty()) {
                return val.trim();
            }

            // Check env var, e.g. AWS_SECRET_PROD_DB_PASSWORD=...
            String envKey = prefix + "_" + sanitized;
            val = System.getenv(envKey);
            if (val != null && !val.trim().isEmpty()) {
                return val.trim();
            }

            // Check direct env var matching inner expression
            val = System.getenv(inner);
            if (val != null && !val.trim().isEmpty()) {
                return val.trim();
            }

            LOGGER.warn("Cloud secret reference [" + expression + "] could not be resolved from environment or properties.");
            return null;
        }

        @Override
        public String getResolverName() {
            return "StandardCloudSecretResolver";
        }
    }
}
