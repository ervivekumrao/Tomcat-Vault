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

package org.apache.tomcat.vault.refresh;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Dynamic Credential Refresher and connection pool re-authentication coordinator.
 * Allows Tomcat connection pools to be refreshed and stale database connections evicted
 * when master credentials or cloud vault secrets rotate without restarting Tomcat.
 */
@SuppressWarnings("unused")
public class VaultCredentialReloader {

    private static final Logger LOGGER = Logger.getLogger(VaultCredentialReloader.class.getName());
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
     * Triggers a credential reload notification across all registered connection pools.
     *
     * @param resourceName JNDI resource name or "*" for all
     */
    public void notifyReload(String resourceName) {
        String target = (resourceName != null && !resourceName.trim().isEmpty()) ? resourceName.trim() : "*";
        LOGGER.log(Level.INFO, "Initiating credential reload for resource: {0}", target);

        for (CredentialChangeListener listener : listeners) {
            try {
                listener.onCredentialChanged(target);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Error notifying CredentialChangeListener: " + e.getMessage(), e);
            }
        }
    }
}
