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

package org.apache.tomcat.dbcp.dbcp2;

import org.apache.tomcat.vault.ReferencePropertyDecryptor;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.Reference;
import java.sql.SQLException;
import java.util.Hashtable;

/**
 * Backward-compatible DataSourceFactory for Tomcat DBCP2 Connection Pool.
 * Delegates credential decryption to {@link ReferencePropertyDecryptor}.
 */
public class EncryptBasicDataSourceFactory extends BasicDataSourceFactory {

    private final ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor();

    public EncryptBasicDataSourceFactory() {
        super();
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws SQLException {
        if (obj instanceof Reference) {
            try {
                decryptor.decryptProperties((Reference) obj);
            } catch (Exception e) {
                throw new SQLException("Failed to decrypt DataSource properties: " + e.getMessage(), e);
            }
        }
        return super.getObjectInstance(obj, name, nameCtx, environment);
    }
}
