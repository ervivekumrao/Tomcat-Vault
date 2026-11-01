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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Composite key provider that evaluates multiple key providers in priority order.
 * Default chain:
 * 1. Java System Property (-Dtomcat.vault.key)
 * 2. Environment Variable (TOMCAT_VAULT_KEY)
 * 3. Filesystem Key File (-Dtomcat.vault.keyfile / TOMCAT_VAULT_KEYFILE)
 * 4. Java KeyStore (-Dtomcat.vault.keystore / TOMCAT_VAULT_KEYSTORE)
 * 5. Fallback Default Development Key
 * @author Vivek Umrao
 */
@SuppressWarnings("unused")
public class CompositeKeyProvider implements KeyProvider {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(CompositeKeyProvider.class);
    private final List<KeyProvider> providers;
    private final Map<String, String> registeredAliasKeys = new ConcurrentHashMap<>();
    private volatile String activeProviderName;

    public CompositeKeyProvider() {
        this(Arrays.asList(
                new SystemPropertyKeyProvider(),
                new EnvironmentKeyProvider(),
                new SecretResolverKeyProvider(),
                new FileKeyProvider(),
                new KeyStoreKeyProvider(),
                new DefaultKeyProvider()
        ));
    }

    public CompositeKeyProvider(List<KeyProvider> providers) {
        this.providers = new CopyOnWriteArrayList<>(providers != null ? providers : Collections.singletonList(new DefaultKeyProvider()));
    }

    /**
     * Registers an explicit secret key for a specific alias or version.
     *
     * @param alias key alias (e.g. "v1", "v2")
     * @param key secret key string
     */
    public void registerKey(String alias, String key) {
        if (alias != null && key != null) {
            registeredAliasKeys.put(alias.trim(), key.trim());
        }
    }

    public void addProviderFirst(KeyProvider provider) {
        if (provider != null) {
            this.providers.add(0, provider);
        }
    }

    public void addProvider(KeyProvider provider) {
        if (provider != null) {
            this.providers.add(provider);
        }
    }

    @Override
    public String getKey() {
        for (KeyProvider provider : providers) {
            if (provider == null) {
                continue;
            }
            try {
                String key = provider.getKey();
                if (key != null && !key.trim().isEmpty()) {
                    this.activeProviderName = provider.getProviderName();
                    LOGGER.debug("Resolved encryption key from provider: " + activeProviderName);
                    return key.trim();
                }
            } catch (SecurityException se) {
                throw se;
            } catch (Exception e) {
                LOGGER.warn("Error resolving key from " + provider.getProviderName() + ": " + e.getMessage(), e);
            }
        }
        return null;
    }

    @Override
    public String getKey(String keyAlias) {
        if (keyAlias == null || keyAlias.trim().isEmpty()) {
            return getKey();
        }

        String registered = registeredAliasKeys.get(keyAlias.trim());
        if (registered != null && !registered.isEmpty()) {
            this.activeProviderName = "RegisteredAliasKey[" + keyAlias.trim() + "]";
            return registered;
        }

        for (KeyProvider provider : providers) {
            if (provider == null) {
                continue;
            }
            try {
                String key = provider.getKey(keyAlias.trim());
                if (key != null && !key.trim().isEmpty()) {
                    this.activeProviderName = provider.getProviderName() + "[alias=" + keyAlias.trim() + "]";
                    return key.trim();
                }
            } catch (SecurityException se) {
                throw se;
            } catch (Exception e) {
                LOGGER.warn("Error resolving alias key from " + provider.getProviderName() + ": " + e.getMessage(), e);
            }
        }
        return getKey();
    }

    @Override
    public String getProviderName() {
        String active = activeProviderName;
        return active != null ? active : "CompositeKeyProvider";
    }
}
