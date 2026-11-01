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

package umrao.tomcat.vault.refresh;

import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;

import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Dynamic Credential Refresher and connection pool re-authentication coordinator.
 * Allows Tomcat connection pools to be refreshed and stale database connections evicted
 * when master credentials or cloud vault secrets rotate without restarting Tomcat.
 * @author Vivek Umrao
 */
@SuppressWarnings("unused")
public class VaultCredentialReloader {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(VaultCredentialReloader.class);
    private static final VaultCredentialReloader INSTANCE = new VaultCredentialReloader();

    private final List<CredentialChangeListener> listeners = new CopyOnWriteArrayList<>();

    private static final class RegisteredDataSource {
        final String resourceName;
        final java.lang.ref.WeakReference<Object> dataSourceRef;

        RegisteredDataSource(String resourceName, Object dataSource) {
            this.resourceName = resourceName;
            this.dataSourceRef = new java.lang.ref.WeakReference<>(dataSource);
        }
    }

    private final List<RegisteredDataSource> registeredDataSources = new CopyOnWriteArrayList<>();

    public static VaultCredentialReloader getInstance() {
        return INSTANCE;
    }

    public interface CredentialChangeListener {
        /**
         * Invoked when credentials for a DataSource resource have changed or rotated.
         *
         * @param resourceName JNDI resource name (e.g. "jdbc/AppDB") or "*" for all
         */
        void onCredentialChanged(String resourceName);
    }

    public void addListener(CredentialChangeListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(CredentialChangeListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    public void clearListeners() {
        listeners.clear();
        registeredDataSources.clear();
    }

    public int getListenerCount() {
        return listeners.size();
    }

    public int getRegisteredDataSourceCount() {
        purgeExpiredDataSources();
        return registeredDataSources.size();
    }

    /**
     * Registers a live JDBC connection pool (e.g. HikariCP, Tomcat JDBC, DBCP2)
     * using a WeakReference to prevent ClassLoader and Metaspace memory leaks across context lifecycles.
     *
     * @param resourceName JNDI resource name (e.g. "jdbc/AppDB")
     * @param dataSource connection pool instance
     */
    public void registerDataSource(String resourceName, Object dataSource) {
        if (resourceName == null || dataSource == null) {
            return;
        }

        purgeExpiredDataSources();

        for (RegisteredDataSource reg : registeredDataSources) {
            Object existing = reg.dataSourceRef.get();
            if (existing != null && existing == dataSource && resourceName.equalsIgnoreCase(reg.resourceName)) {
                return; // already registered
            }
        }

        registeredDataSources.add(new RegisteredDataSource(resourceName, dataSource));
    }

    public void unregisterDataSource(String resourceName) {
        if (resourceName == null) return;
        registeredDataSources.removeIf(reg -> resourceName.equalsIgnoreCase(reg.resourceName));
    }

    public void unregisterDataSource(Object dataSource) {
        if (dataSource == null) return;
        registeredDataSources.removeIf(reg -> {
            Object obj = reg.dataSourceRef.get();
            return obj == null || obj == dataSource;
        });
    }

    private void purgeExpiredDataSources() {
        registeredDataSources.removeIf(reg -> reg.dataSourceRef.get() == null);
    }

    private void evictPoolConnections(Object dataSource) {
        try {
            Class<?> clazz = dataSource.getClass();

            // 1. HikariCP: dataSource.getHikariPoolMXBean().softEvictConnections()
            Method getMxBean = findMethod(clazz, "getHikariPoolMXBean");
            if (getMxBean != null) {
                Object mxBean = getMxBean.invoke(dataSource);
                if (mxBean != null) {
                    Method softEvict = findMethod(mxBean.getClass(), "softEvictConnections");
                    if (softEvict != null) {
                        softEvict.invoke(mxBean);
                        LOGGER.info("Executed softEvictConnections on HikariCP pool.");
                        return;
                    }
                }
            }

            // 2. Tomcat JDBC Pool: dataSource.purge()
            Method purgeMethod = findMethod(clazz, "purge");
            if (purgeMethod != null) {
                purgeMethod.invoke(dataSource);
                LOGGER.info("Executed purge on Tomcat JDBC pool.");
                return;
            }

            // 3. DBCP2: dataSource.restart() or dataSource.evict()
            Method restartMethod = findMethod(clazz, "restart");
            if (restartMethod != null) {
                restartMethod.invoke(dataSource);
                LOGGER.info("Executed restart on DBCP2 pool.");
                return;
            }
            Method evictMethod = findMethod(clazz, "evict");
            if (evictMethod != null) {
                evictMethod.invoke(dataSource);
                LOGGER.info("Executed evict on DBCP2 pool.");
                return;
            }

            // 4. Generic evictConnections if supported
            Method genericEvict = findMethod(clazz, "evictConnections");
            if (genericEvict != null) {
                genericEvict.invoke(dataSource);
                LOGGER.info("Executed evictConnections on pool.");
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to evict connections on pool: " + e.getMessage(), e);
        }
    }

    private static final java.util.concurrent.ConcurrentMap<String, Method> METHOD_CACHE = new java.util.concurrent.ConcurrentHashMap<>();
    private static final Method NO_METHOD;
    static {
        try {
            NO_METHOD = VaultCredentialReloader.class.getDeclaredMethod("noMethodSentinel");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static void noMethodSentinel() {
    }

    private static Method findMethod(Class<?> clazz, String name) {
        String cacheKey = clazz.getName() + "#" + name;
        Method cached = METHOD_CACHE.get(cacheKey);
        if (cached != null) {
            return cached == NO_METHOD ? null : cached;
        }

        Method found = null;
        try {
            found = clazz.getMethod(name);
            found.setAccessible(true);
        } catch (NoSuchMethodException e) {
            try {
                found = clazz.getDeclaredMethod(name);
                found.setAccessible(true);
            } catch (NoSuchMethodException ex) {
                // Method not present on target class
            }
        }
        METHOD_CACHE.put(cacheKey, found != null ? found : NO_METHOD);
        return found;
    }

    /**
     * Triggers a credential reload notification across all registered connection pools.
     *
     * @param resourceName JNDI resource name or "*" for all
     */
    public void notifyReload(String resourceName) {
        String target = (resourceName != null && !resourceName.trim().isEmpty()) ? resourceName.trim() : "*";
        LOGGER.info("Initiating credential reload for resource: " + target);

        // 1. Evict connections from matching live DataSources
        purgeExpiredDataSources();
        for (RegisteredDataSource reg : registeredDataSources) {
            if ("*".equals(target) || reg.resourceName.equalsIgnoreCase(target)) {
                Object ds = reg.dataSourceRef.get();
                if (ds != null) {
                    LOGGER.info("Evicting stale connections for resource [" + reg.resourceName + "] following credential update.");
                    evictPoolConnections(ds);
                }
            }
        }

        // 2. Notify custom listeners
        for (CredentialChangeListener listener : listeners) {
            try {
                listener.onCredentialChanged(target);
            } catch (Exception e) {
                LOGGER.warn("Error notifying CredentialChangeListener: " + e.getMessage(), e);
            }
        }
    }
}
