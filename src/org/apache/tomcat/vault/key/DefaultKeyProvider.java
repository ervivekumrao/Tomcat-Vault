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

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Fallback key provider that supplies the built-in development key.
 * Logs a high-visibility warning to remind administrators to supply an external key in production.
 */
public class DefaultKeyProvider implements KeyProvider {

    private static final Logger LOGGER = Logger.getLogger(DefaultKeyProvider.class.getName());
    private static final AtomicBoolean WARNING_LOGGED = new AtomicBoolean(false);

    @Override
    public String getKey() {
        if (WARNING_LOGGED.compareAndSet(false, true)) {
            LOGGER.log(Level.WARNING,
                    "[SECURITY WARNING] Tomcat Vault is using the default development fallback key! " +
                    "For production deployments, please configure an external key via environment variable (" +
                    VaultConstants.ENV_KEY + "), system property (-D" + VaultConstants.SYS_PROP_KEY + "), " +
                    "or key file (-D" + VaultConstants.SYS_PROP_KEYFILE + ").");
        }
        return VaultConstants.DEFAULT_DEV_KEY;
    }

    @Override
    public String getProviderName() {
        return "DefaultDevelopmentKeyProvider";
    }
}
