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

package umrao.encrypt;

import org.apache.tomcat.vault.VaultConstants;

/**
 * Backward-compatibility wrapper for Constants.
 * Directs to {@link VaultConstants}.
 */
@SuppressWarnings("unused")
public final class Constants {

    public static final String ENCRYPTION_ALGO = "AES";
    public static final String ENCRYPTION_KEY = VaultConstants.DEFAULT_DEV_KEY;
    public static final String IV = VaultConstants.DEFAULT_DEV_IV;
    public static final String HASHING_ALGO = VaultConstants.HASH_ALGO_SHA512;

    private Constants() {
        // Prevent instantiation
    }
}
