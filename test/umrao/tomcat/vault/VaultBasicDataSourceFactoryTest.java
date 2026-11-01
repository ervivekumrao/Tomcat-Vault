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

import javax.naming.Reference;
import javax.naming.StringRefAddr;
import java.sql.SQLException;
import java.util.Hashtable;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class VaultBasicDataSourceFactoryTest {

    @Test
    @DisplayName("VaultBasicDataSourceFactory getObjectInstance with non-Reference, Reference, and Decryption failure")
    public void testVaultBasicDataSourceFactory() throws Exception {
        VaultBasicDataSourceFactory factory = new VaultBasicDataSourceFactory();

        // Non-reference object
        Object nonRefResult = factory.getObjectInstance("not-a-reference", null, null, new Hashtable<>());
        assertNull(nonRefResult);

        // Reference with dummy class
        Reference reference = new Reference("non.existent.DataSource");
        reference.add(new StringRefAddr("username", "plainUser"));
        Object refResult = factory.getObjectInstance(reference, null, null, new Hashtable<>());
        assertNull(refResult);

        // Reference with corrupted encrypted attribute triggering SQLException
        Reference corruptedRef = new Reference("non.existent.DataSource");
        corruptedRef.add(new StringRefAddr("password", "ENC(corrupted-payload)"));
        assertThrows(SQLException.class, () -> factory.getObjectInstance(corruptedRef, null, null, new Hashtable<>()));
    }
}
