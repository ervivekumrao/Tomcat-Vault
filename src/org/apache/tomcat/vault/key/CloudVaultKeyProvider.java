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

/**
 * Extension SPI interface for integrating cloud secret vaults such as
 * AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, or Google Cloud Secret Manager.
 * Clients can implement this interface and register it via standard SPI (META-INF/services)
 * or pass it directly to the CompositeKeyProvider.
 */
@SuppressWarnings("unused")
public interface CloudVaultKeyProvider extends KeyProvider {

    /**
     * Optional secret identifier or vault path (e.g. "secret/data/tomcat/database#encryption_key").
     *
     * @return secret path or identifier
     */
    String getVaultSecretPath();

    /**
     * Checks if the cloud vault connection is healthy and authenticated.
     *
     * @return true if available
     */
    boolean isAvailable();
}
