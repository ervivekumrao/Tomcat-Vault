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

package umrao.tomcat.vault.exception;

import java.io.Serial;

/**
 * Base runtime exception for all Tomcat Vault operations.
 * @author Vivek Umrao
 */
public class VaultException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    public VaultException(String message) {
        super(message);
    }

    public VaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
