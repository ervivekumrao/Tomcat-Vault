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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import umrao.tomcat.vault.exception.ConfigurationException;
import umrao.tomcat.vault.exception.DecryptionException;
import umrao.tomcat.vault.exception.KeyResolutionException;
import umrao.tomcat.vault.exception.SecretResolutionException;
import umrao.tomcat.vault.exception.VaultException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class VaultExceptionTest {

    @Test
    @DisplayName("Exception hierarchy: VaultException and specialized subclasses")
    void testExceptionHierarchy() {
        VaultException ve = new VaultException("Base vault exception", new RuntimeException("root"));
        assertEquals("Base vault exception", ve.getMessage());
        assertNotNull(ve.getCause());

        Throwable rootCause = new IllegalStateException("cause");

        DecryptionException de = new DecryptionException("Decryption error", rootCause);
        assertInstanceOf(VaultException.class, de);
        assertInstanceOf(RuntimeException.class, de);
        DecryptionException deSingle = new DecryptionException("Decryption error single");
        assertEquals("Decryption error single", deSingle.getMessage());

        KeyResolutionException kre = new KeyResolutionException("Key error", rootCause);
        assertInstanceOf(VaultException.class, kre);
        assertEquals(rootCause, kre.getCause());
        KeyResolutionException kreSingle = new KeyResolutionException("Key error single");
        assertEquals("Key error single", kreSingle.getMessage());

        ConfigurationException ce = new ConfigurationException("Config error", rootCause);
        assertInstanceOf(VaultException.class, ce);
        assertEquals(rootCause, ce.getCause());
        ConfigurationException ceSingle = new ConfigurationException("Config error single");
        assertEquals("Config error single", ceSingle.getMessage());

        SecretResolutionException sre = new SecretResolutionException("Secret error", rootCause);
        assertInstanceOf(VaultException.class, sre);
        assertEquals(rootCause, sre.getCause());
        SecretResolutionException sreSingle = new SecretResolutionException("Secret error single");
        assertEquals("Secret error single", sreSingle.getMessage());
    }
}
