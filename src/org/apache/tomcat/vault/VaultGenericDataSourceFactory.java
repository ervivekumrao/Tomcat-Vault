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
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.spi.ObjectFactory;
import java.lang.reflect.Method;
import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Universal JNDI ObjectFactory adapter that can wrap any JDBC connection pool
 * (such as Vibur DBCP, C3P0, BoneCP, or custom enterprise pools).
 * Decrypts all sensitive properties in the {@link Reference} before passing them
 * to the delegate factory specified via the {@code delegateFactory} configuration attribute.
 */
public class VaultGenericDataSourceFactory implements ObjectFactory {

    private static final Logger LOGGER = Logger.getLogger(VaultGenericDataSourceFactory.class.getName());
    public static final String DELEGATE_FACTORY_PROPERTY = "delegateFactory";

    private final ReferencePropertyDecryptor decryptor;
    private final String defaultDelegateClassName;

    public VaultGenericDataSourceFactory() {
        this(new ReferencePropertyDecryptor(), "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory");
    }

    public VaultGenericDataSourceFactory(String defaultDelegateClassName) {
        this(new ReferencePropertyDecryptor(), defaultDelegateClassName);
    }

    public VaultGenericDataSourceFactory(ReferencePropertyDecryptor decryptor, String defaultDelegateClassName) {
        this.decryptor = decryptor != null ? decryptor : new ReferencePropertyDecryptor();
        this.defaultDelegateClassName = defaultDelegateClassName;
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        String targetFactoryClassName = defaultDelegateClassName;

        if (obj instanceof Reference) {
            Reference ref = (Reference) obj;
            decryptor.decryptProperties(ref);

            RefAddr delegateAddr = ref.get(DELEGATE_FACTORY_PROPERTY);
            if (delegateAddr != null && delegateAddr.getContent() != null) {
                targetFactoryClassName = delegateAddr.getContent().toString().trim();
            }
        }

        if (targetFactoryClassName == null || targetFactoryClassName.isEmpty()) {
            throw new IllegalArgumentException("No delegateFactory specified for VaultGenericDataSourceFactory");
        }

        try {
            Class<?> factoryClass = Class.forName(targetFactoryClassName, true, Thread.currentThread().getContextClassLoader());
            Object factoryInstance = factoryClass.getDeclaredConstructor().newInstance();
            Method method = factoryClass.getMethod("getObjectInstance", Object.class, Name.class, Context.class, Hashtable.class);
            return method.invoke(factoryInstance, obj, name, nameCtx, environment);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to delegate to factory class: " + targetFactoryClassName, e);
            throw e;
        }
    }
}
