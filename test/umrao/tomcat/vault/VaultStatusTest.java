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

package umrao.tomcat.vault;

import umrao.tomcat.vault.jmx.VaultStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Vivek Umrao
 */
public class VaultStatusTest {

    @AfterEach
    void tearDown() {
        VaultStatus.unregisterMBean();
    }

    @Test
    @DisplayName("VaultStatusMXBean JMX management MBean")
    void testVaultStatusMBean() {
        VaultStatus.registerMBean();
        VaultStatus status = VaultStatus.getInstance();

        assertNotNull(status.getActiveKeyProvider());
        assertFalse(status.isStrictMode());
        assertTrue(status.getReloadListenerCount() >= 0);

        assertDoesNotThrow(status::clearKeyCache);
        assertDoesNotThrow(() -> status.reloadCredentials("*"));

        VaultStatus.unregisterMBean();
    }
}
