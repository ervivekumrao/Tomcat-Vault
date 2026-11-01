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

package umrao.tomcat.vault;

import umrao.tomcat.vault.refresh.VaultCredentialReloader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class VaultCredentialReloaderTest {

    @AfterEach
    void tearDown() {
        VaultCredentialReloader.getInstance().clearListeners();
    }

    @Test
    @DisplayName("VaultCredentialReloader registers listeners and broadcasts reload events")
    void testCredentialReloader() {
        VaultCredentialReloader reloader = VaultCredentialReloader.getInstance();
        reloader.clearListeners();

        AtomicBoolean listenerCalled = new AtomicBoolean(false);
        AtomicReference<String> targetResource = new AtomicReference<>();

        VaultCredentialReloader.CredentialChangeListener listener = resource -> {
            listenerCalled.set(true);
            targetResource.set(resource);
        };

        reloader.addListener(listener);
        assertEquals(1, reloader.getListenerCount());

        reloader.notifyReload("jdbc/ProductionDB");
        assertTrue(listenerCalled.get());
        assertEquals("jdbc/ProductionDB", targetResource.get());

        // Exception in listener is caught gracefully
        reloader.addListener(res -> {
            throw new RuntimeException("Simulated error in listener");
        });
        assertDoesNotThrow(() -> reloader.notifyReload("jdbc/AppDB"));

        reloader.removeListener(listener);
        assertEquals(1, reloader.getListenerCount());
        reloader.clearListeners();
        assertEquals(0, reloader.getListenerCount());
    }

    @Test
    @DisplayName("VaultCredentialReloader pool eviction helper")
    void testVaultCredentialReloaderPoolRegistration() {
        VaultCredentialReloader reloader = VaultCredentialReloader.getInstance();
        AtomicBoolean evicted = new AtomicBoolean(false);

        Object mockPool = new Object() {
            @SuppressWarnings("unused")
            public void purge() {
                evicted.set(true);
            }
        };

        reloader.registerDataSource("jdbc/MockPurgeDB", mockPool);
        reloader.notifyReload("jdbc/MockPurgeDB");

        assertTrue(evicted.get(), "purge() should have been called upon credential reload");
    }
}
