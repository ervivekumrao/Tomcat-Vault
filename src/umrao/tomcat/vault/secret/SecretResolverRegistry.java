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
 * @author Vivek Umrao
 */
@SuppressWarnings("unused")
public class SecretResolverRegistry {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(SecretResolverRegistry.class);
    private static final SecretResolverRegistry INSTANCE = new SecretResolverRegistry();

    private static final long DEFAULT_CACHE_TTL_MS = 300_000L; // 5 minutes default

    private static final class CachedSecret {
        final String value;
        final long expiresAt;

        CachedSecret(String value, long expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }

        boolean isExpired() {
            return expiresAt > 0 && System.currentTimeMillis() > expiresAt;
        }
    }

    private final List<SecretResolver> resolvers = new CopyOnWriteArrayList<>();
    private final java.util.concurrent.ConcurrentMap<String, CachedSecret> secretCache = new java.util.concurrent.ConcurrentHashMap<>();

    public static SecretResolverRegistry getInstance() {
        return INSTANCE;
    }

    public SecretResolverRegistry() {
        registerDefaultResolvers();
    }

    public void clearCache() {
        secretCache.clear();
    }

    private long resolveCacheTtl() {
        String prop = System.getProperty("tomcat.vault.secret.cache.ttl.ms");
        if (prop == null || prop.trim().isEmpty()) {
            prop = System.getenv("TOMCAT_VAULT_SECRET_CACHE_TTL_MS");
        }
        if (prop != null && !prop.trim().isEmpty()) {
            try {
                return Long.parseLong(prop.trim());
            } catch (NumberFormatException ignored) {
            }
        }
        return DEFAULT_CACHE_TTL_MS;
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
        secretCache.clear();
    }

    public void resetDefaultResolvers() {
        resolvers.clear();
        secretCache.clear();
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

        long ttl = resolveCacheTtl();
        if (ttl > 0) {
            CachedSecret cached = secretCache.get(trimmed);
            if (cached != null && !cached.isExpired()) {
                return cached.value;
            }
        }

        boolean matchedAny = false;

        for (SecretResolver resolver : resolvers) {
            if (resolver.supports(trimmed)) {
                matchedAny = true;
                try {
                    String resolved = resolver.resolve(trimmed);
                    if (resolved != null) {
                        if (ttl > 0) {
                            secretCache.put(trimmed, new CachedSecret(resolved, System.currentTimeMillis() + ttl));
                        }
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

    private static final java.util.regex.Pattern EMBEDDED_SECRET_PATTERN =
            java.util.regex.Pattern.compile("(?i)(AWS_SECRET|VAULT|AZURE_VAULT|GCP_SECRET)\\(([^()]+)\\)");

    /**
     * Checks if a value contains one or more embedded cloud secret expressions (e.g. AWS_SECRET(...) inside a URL).
     *
     * @param value candidate string
     * @return true if embedded secret expressions are present
     */
    public boolean hasResolvable(String value) {
        if (value == null || value.trim().isEmpty()) {
            return false;
        }
        if (isResolvable(value)) {
            return true;
        }
        return EMBEDDED_SECRET_PATTERN.matcher(value).find();
    }

    /**
     * Resolves all embedded cloud secret expressions within a composite string (such as a JDBC URL).
     * Non-matching portions of the string are preserved unchanged.
     *
     * @param value candidate string with embedded expressions
     * @return resolved string
     */
    public String resolveEmbedded(String value) {
        if (value == null || value.trim().isEmpty()) {
            return value;
        }
        if (isResolvable(value)) {
            return resolve(value);
        }
        java.util.regex.Matcher matcher = EMBEDDED_SECRET_PATTERN.matcher(value);
        if (!matcher.find()) {
            return value;
        }
        StringBuilder sb = new StringBuilder();
        int lastEnd = 0;
        matcher.reset();
        while (matcher.find()) {
            sb.append(value, lastEnd, matcher.start());
            String token = matcher.group(0);
            String resolved = resolve(token);
            sb.append(resolved != null ? resolved : token);
            lastEnd = matcher.end();
        }
        sb.append(value.substring(lastEnd));
        return sb.toString();
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
