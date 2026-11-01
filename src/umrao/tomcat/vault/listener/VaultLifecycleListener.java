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

package umrao.tomcat.vault.listener;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import umrao.tomcat.vault.VaultConstants;
import umrao.tomcat.vault.VaultCrypto;
import umrao.tomcat.vault.jmx.VaultStatus;
import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;

import javax.crypto.Cipher;

/**
 * Enterprise Apache Tomcat container lifecycle listener for {@code server.xml}.
 * Configurable via:
 * <pre>{@code
 * <Listener className="umrao.tomcat.vault.listener.VaultLifecycleListener"
 *           strictMode="true"
 *           jmxEnabled="true" />
 * }</pre>
 * Validates cryptographic requirements (JCE unlimited strength, key provider health, strict mode),
 * and manages JMX monitoring and audit logging lifecycles.
 */
public class VaultLifecycleListener implements LifecycleListener {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(VaultLifecycleListener.class);

    private boolean strictMode = false;
    private boolean jmxEnabled = true;

    public boolean isStrictMode() {
        return strictMode;
    }

    public void setStrictMode(boolean strictMode) {
        this.strictMode = strictMode;
    }

    public boolean isJmxEnabled() {
        return jmxEnabled;
    }

    public void setJmxEnabled(boolean jmxEnabled) {
        this.jmxEnabled = jmxEnabled;
    }

    @Override
    public void lifecycleEvent(LifecycleEvent event) {
        if (event == null || event.getType() == null) {
            return;
        }

        String type = event.getType();
        if (Lifecycle.BEFORE_START_EVENT.equals(type) || Lifecycle.START_EVENT.equals(type)) {
            onServerStart();
        } else if (Lifecycle.STOP_EVENT.equals(type) || Lifecycle.AFTER_STOP_EVENT.equals(type)) {
            onServerStop();
        }
    }

    private void onServerStart() {
        LOGGER.info("Initializing Tomcat Vault Lifecycle Listener (v2.0.0)...");

        // 1. Validate JCE strength
        try {
            int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            if (maxKeyLen < 256) {
                String msg = "JCE Jurisdiction Policy restricts AES key length to " + maxKeyLen + "-bit. AES-256 requires unlimited strength jurisdiction policy.";
                LOGGER.warn(msg);
                if (strictMode) {
                    throw new SecurityException("Tomcat Vault startup aborted: " + msg);
                }
            } else {
                LOGGER.info("JCE Unlimited Strength Jurisdiction validated (AES max key length: " + maxKeyLen + "-bit).");
            }
        } catch (SecurityException se) {
            throw se;
        } catch (Exception e) {
            LOGGER.warn("Failed to check JCE key length: " + e.getMessage());
        }

        // 2. Configure strict mode if requested
        if (strictMode) {
            System.setProperty(VaultConstants.SYS_PROP_STRICT, "true");
        }

        // 3. Verify key provider status
        try {
            VaultCrypto crypto = new VaultCrypto();
            String activeKey = crypto.getKeyProvider().getKey();
            boolean isDev = activeKey == null || VaultConstants.DEFAULT_DEV_KEY.equals(activeKey);
            if (isDev) {
                String warning = "Tomcat Vault is using the fallback default development key or no key was found! Set "
                        + VaultConstants.ENV_KEY + " or -D" + VaultConstants.SYS_PROP_KEY + " for production.";
                LOGGER.warn("[SECURITY WARNING] " + warning);
                if (strictMode) {
                    throw new SecurityException("Tomcat Vault strict mode violation: fallback to default development key is forbidden. " + warning);
                }
            } else {
                LOGGER.info("Loaded production encryption key via " + crypto.getKeyProvider().getProviderName());
            }
        } catch (SecurityException se) {
            throw se;
        } catch (Exception e) {
            LOGGER.error("Key provider initialization failure: " + e.getMessage(), e);
        }

        // 4. Register JMX MBean
        if (jmxEnabled) {
            VaultStatus.registerMBean();
        }
    }

    private void onServerStop() {
        LOGGER.info("Stopping Tomcat Vault...");
        if (jmxEnabled) {
            VaultStatus.unregisterMBean();
        }
        VaultLogFactory.closeFileHandlers();
    }
}
