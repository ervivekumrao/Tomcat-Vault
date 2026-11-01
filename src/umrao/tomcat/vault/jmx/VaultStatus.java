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

package umrao.tomcat.vault.jmx;

import umrao.tomcat.vault.VaultConstants;
import umrao.tomcat.vault.VaultCrypto;
import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;
import umrao.tomcat.vault.refresh.VaultCredentialReloader;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.lang.management.ManagementFactory;

/**
 * Implementation of {@link VaultStatusMXBean} registered with JMX.
 */
public class VaultStatus implements VaultStatusMXBean {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(VaultStatus.class);
    public static final String JMX_OBJECT_NAME = "TomcatVault:type=Status";
    private static final VaultStatus INSTANCE = new VaultStatus();
    private static volatile boolean registered = false;

    public static VaultStatus getInstance() {
        return INSTANCE;
    }

    /**
     * Registers the Tomcat Vault MBean with the platform MBeanServer.
     */
    public static synchronized void registerMBean() {
        if (!registered) {
            try {
                MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
                ObjectName name = new ObjectName(JMX_OBJECT_NAME);
                if (!mbs.isRegistered(name)) {
                    mbs.registerMBean(INSTANCE, name);
                    registered = true;
                    LOGGER.info("Registered Tomcat Vault JMX MBean: " + JMX_OBJECT_NAME);
                }
            } catch (Exception e) {
                LOGGER.warn("Failed to register Tomcat Vault JMX MBean: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Unregisters the Tomcat Vault MBean from the platform MBeanServer.
     */
    public static synchronized void unregisterMBean() {
        if (registered) {
            try {
                MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
                ObjectName name = new ObjectName(JMX_OBJECT_NAME);
                if (mbs.isRegistered(name)) {
                    mbs.unregisterMBean(name);
                }
            } catch (Exception ignored) {
            } finally {
                registered = false;
            }
        }
    }

    @Override
    public String getActiveKeyProvider() {
        try {
            return new VaultCrypto().getKeyProvider().getProviderName();
        } catch (Exception e) {
            return "Unavailable: " + e.getMessage();
        }
    }

    @Override
    public boolean isStrictMode() {
        return Boolean.getBoolean(VaultConstants.SYS_PROP_STRICT)
                || "true".equalsIgnoreCase(System.getenv(VaultConstants.ENV_STRICT));
    }

    @Override
    public int getReloadListenerCount() {
        return VaultCredentialReloader.getInstance().getListenerCount();
    }

    @Override
    public void clearKeyCache() {
        VaultCrypto.clearKeyCache();
        LOGGER.info("Cryptographic key cache cleared via JMX.");
    }

    @Override
    public void reloadCredentials(String resourceName) {
        VaultCredentialReloader.getInstance().notifyReload(resourceName);
    }
}
