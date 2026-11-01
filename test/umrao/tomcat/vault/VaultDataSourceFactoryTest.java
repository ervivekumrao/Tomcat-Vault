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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.naming.Reference;
import javax.naming.StringRefAddr;
import java.util.Hashtable;

import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * @author Vivek Umrao
 */
public class VaultDataSourceFactoryTest {

    @Test
    @DisplayName("VaultDataSourceFactory getObjectInstance with non-Reference and Reference")
    public void testVaultDataSourceFactory() throws Exception {
        VaultDataSourceFactory factory = new VaultDataSourceFactory();

        // Non-reference object should return null or pass to super
        Object nonRefResult = factory.getObjectInstance("not-a-reference", null, null, new Hashtable<>());
        assertNull(nonRefResult);

        // Reference with dummy class
        Reference reference = new Reference("non.existent.DataSource");
        reference.add(new StringRefAddr("username", "plainUser"));
        Object refResult = factory.getObjectInstance(reference, null, null, new Hashtable<>());
        assertNull(refResult);
    }
}
