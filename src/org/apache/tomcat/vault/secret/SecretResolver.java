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

package org.apache.tomcat.vault.secret;

/**
 * Service Provider Interface (SPI) for dynamically resolving external secrets from
 * cloud providers and enterprise secret stores (e.g. AWS Secrets Manager, HashiCorp Vault, Azure Key Vault).
 */
public interface SecretResolver {

    /**
     * Determines whether this resolver can handle the specified expression.
     * (e.g. starts with "AWS_SECRET(", "VAULT(", or "AZURE_VAULT(").
     *
     * @param expression candidate expression
     * @return true if supported
     */
    boolean supports(String expression);

    /**
     * Resolves the secret value from the external secret store.
     *
     * @param expression secret identifier expression
     * @return resolved cleartext secret value
     */
    String resolve(String expression);

    /**
     * Returns the name of this secret resolver.
     *
     * @return resolver identifier
     */
    String getResolverName();
}
