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

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import umrao.tomcat.vault.listener.VaultLifecycleListener;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class VaultLifecycleListenerTest {

    @AfterEach
    void tearDown() {
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
    }

    @Test
    @DisplayName("VaultLifecycleListener start and stop lifecycle events")
    void testVaultLifecycleListener() {
        VaultLifecycleListener listener = new VaultLifecycleListener();
        listener.setStrictMode(false);
        listener.setJmxEnabled(true);

        assertTrue(listener.isJmxEnabled());
        assertFalse(listener.isStrictMode());

        Lifecycle dummyLifecycle = new org.apache.catalina.util.LifecycleBase() {
            @Override protected void initInternal() {}
            @Override protected void startInternal() {}
            @Override protected void stopInternal() {}
            @Override protected void destroyInternal() {}
        };

        // Start event
        LifecycleEvent startEvent = new LifecycleEvent(dummyLifecycle, Lifecycle.START_EVENT, null);
        assertDoesNotThrow(() -> listener.lifecycleEvent(startEvent));

        // Stop event
        LifecycleEvent stopEvent = new LifecycleEvent(dummyLifecycle, Lifecycle.STOP_EVENT, null);
        assertDoesNotThrow(() -> listener.lifecycleEvent(stopEvent));

        // Null and unknown events pass safely
        assertDoesNotThrow(() -> listener.lifecycleEvent(null));
        assertDoesNotThrow(() -> listener.lifecycleEvent(new LifecycleEvent(dummyLifecycle, "UNKNOWN_EVENT", null)));
    }

    @Test
    @DisplayName("VaultLifecycleListener BEFORE_START and strict mode violation")
    void testVaultLifecycleListenerStrictModeViolation() {
        VaultLifecycleListener listener = new VaultLifecycleListener();
        listener.setStrictMode(true);

        Lifecycle dummy = new org.apache.catalina.util.LifecycleBase() {
            @Override protected void initInternal() {}
            @Override protected void startInternal() {}
            @Override protected void stopInternal() {}
            @Override protected void destroyInternal() {}
        };

        LifecycleEvent beforeStart = new LifecycleEvent(dummy, Lifecycle.BEFORE_START_EVENT, null);
        assertThrows(SecurityException.class, () -> listener.lifecycleEvent(beforeStart));

        LifecycleEvent afterStop = new LifecycleEvent(dummy, Lifecycle.AFTER_STOP_EVENT, null);
        assertDoesNotThrow(() -> listener.lifecycleEvent(afterStop));
    }
}
