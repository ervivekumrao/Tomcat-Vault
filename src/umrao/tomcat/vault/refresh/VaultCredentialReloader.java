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
 */
@SuppressWarnings("unused")
public class VaultCredentialReloader {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(VaultCredentialReloader.class);
    private static final VaultCredentialReloader INSTANCE = new VaultCredentialReloader();

    private final List<CredentialChangeListener> listeners = new CopyOnWriteArrayList<>();

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
    }

    public int getListenerCount() {
        return listeners.size();
    }

    /**
     * Registers a live JDBC connection pool (e.g. HikariCP, Tomcat JDBC, DBCP2)
     * so that its active/idle connections are automatically evicted upon credential rotation.
     *
     * @param resourceName JNDI resource name (e.g. "jdbc/AppDB")
     * @param dataSource connection pool instance
     */
    public void registerDataSource(String resourceName, Object dataSource) {
        if (resourceName == null || dataSource == null) {
            return;
        }

        addListener(target -> {
            if ("*".equals(target) || resourceName.equalsIgnoreCase(target)) {
                LOGGER.info("Evicting stale connections for resource [" + resourceName + "] following credential update.");
                evictPoolConnections(dataSource);
            }
        });
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

            // 3. Generic close / restart if supported
            Method evictMethod = findMethod(clazz, "evictConnections");
            if (evictMethod != null) {
                evictMethod.invoke(dataSource);
                LOGGER.info("Executed evictConnections on pool.");
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to evict connections on pool: " + e.getMessage(), e);
        }
    }

    private static Method findMethod(Class<?> clazz, String name) {
        try {
            Method m = clazz.getMethod(name);
            m.setAccessible(true);
            return m;
        } catch (NoSuchMethodException e) {
            try {
                Method m = clazz.getDeclaredMethod(name);
                m.setAccessible(true);
                return m;
            } catch (NoSuchMethodException ex) {
                return null;
            }
        }
    }

    /**
     * Triggers a credential reload notification across all registered connection pools.
     *
     * @param resourceName JNDI resource name or "*" for all
     */
    public void notifyReload(String resourceName) {
        String target = (resourceName != null && !resourceName.trim().isEmpty()) ? resourceName.trim() : "*";
        LOGGER.info("Initiating credential reload for resource: " + target);

        for (CredentialChangeListener listener : listeners) {
            try {
                listener.onCredentialChanged(target);
            } catch (Exception e) {
                LOGGER.warn("Error notifying CredentialChangeListener: " + e.getMessage(), e);
            }
        }
    }
}
