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

package org.apache.tomcat.vault;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.Reference;
import javax.naming.spi.ObjectFactory;
import java.lang.reflect.Method;
import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * High-performance JNDI ObjectFactory for HikariCP connection pools in Apache Tomcat.
 * Intercepts connection pool definitions in {@code context.xml} or {@code server.xml},
 * decrypts encrypted credentials (such as {@code dataSource.password}, {@code password},
 * {@code dataSource.user}, and {@code jdbcUrl}), and delegates to HikariCP's JNDI factory.
 */
public class VaultHikariDataSourceFactory implements ObjectFactory {

    private static final Logger LOGGER = Logger.getLogger(VaultHikariDataSourceFactory.class.getName());
    private static final String HIKARI_JNDI_FACTORY_CLASS = "com.zaxxer.hikari.HikariJNDIFactory";

    private final ReferencePropertyDecryptor decryptor;
    private final ObjectFactory delegateFactory;

    public VaultHikariDataSourceFactory() {
        this(new ReferencePropertyDecryptor(), null);
    }

    public VaultHikariDataSourceFactory(ReferencePropertyDecryptor decryptor) {
        this(decryptor, null);
    }

    public VaultHikariDataSourceFactory(ReferencePropertyDecryptor decryptor, ObjectFactory delegateFactory) {
        this.decryptor = decryptor != null ? decryptor : new ReferencePropertyDecryptor();
        this.delegateFactory = delegateFactory;
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        if (obj instanceof Reference) {
            Reference ref = (Reference) obj;
            decryptor.decryptProperties(ref);
        }

        if (delegateFactory != null) {
            return delegateFactory.getObjectInstance(obj, name, nameCtx, environment);
        }

        // Delegate to HikariCP's HikariJNDIFactory dynamically
        try {
            Class<?> hikariFactoryClass = Class.forName(HIKARI_JNDI_FACTORY_CLASS, true, Thread.currentThread().getContextClassLoader());
            Object factoryInstance = hikariFactoryClass.getDeclaredConstructor().newInstance();
            Method method = hikariFactoryClass.getMethod("getObjectInstance", Object.class, Name.class, Context.class, Hashtable.class);
            return method.invoke(factoryInstance, obj, name, nameCtx, environment);
        } catch (ClassNotFoundException e) {
            LOGGER.log(Level.SEVERE, "HikariCP JNDI Factory (" + HIKARI_JNDI_FACTORY_CLASS + ") not found on classpath. Ensure HikariCP.jar is placed in Tomcat's lib/ directory.", e);
            throw e;
        }
    }
}
