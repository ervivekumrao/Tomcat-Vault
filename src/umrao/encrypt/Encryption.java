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

import org.apache.tomcat.vault.ReferencePropertyDecryptor;
import org.apache.tomcat.vault.VaultCrypto;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.naming.Reference;
import java.nio.charset.StandardCharsets;

import static umrao.encrypt.Constants.ENCRYPTION_ALGO;
import static umrao.encrypt.Constants.ENCRYPTION_KEY;

/**
 * Backward-compatibility facade for Encryption.
 * Delegates to modern {@link VaultCrypto} and {@link ReferencePropertyDecryptor}.
 * Prevents cleartext credential logging and supports both AES-256-GCM and legacy formats.
 */
@SuppressWarnings("unused")
public class Encryption {

    private final VaultCrypto crypto;
    private final ReferencePropertyDecryptor propertyDecryptor;

    public Encryption() {
        this(ENCRYPTION_KEY, ENCRYPTION_ALGO);
    }

    public Encryption(String encryptionKey, String encryptionAlgorithm) {
        String key = (encryptionKey == null || encryptionKey.isEmpty()) ? ENCRYPTION_KEY : encryptionKey;
        this.crypto = new VaultCrypto(key);
        this.propertyDecryptor = new ReferencePropertyDecryptor(this.crypto);
    }

    public String getEncryptedMessage(String msg) {
        if (msg == null || msg.isEmpty()) {
            throw new RuntimeException("Encryption message is empty or null.");
        }
        return crypto.encrypt(msg);
    }

    public String getDecryptedMessage(String msg) {
        if (msg == null || msg.isEmpty()) {
            throw new RuntimeException("Decryption message is empty or null.");
        }
        return crypto.decrypt(msg);
    }

    public SecretKey generateStaticSecretKey() {
        return VaultCrypto.getOrCreateLegacyCbcSecretKey(ENCRYPTION_KEY);
    }

    public IvParameterSpec getIvParameterSpec() {
        return new IvParameterSpec(Constants.IV.getBytes(StandardCharsets.UTF_8));
    }

    public void decryptProperties(Reference reference) {
        propertyDecryptor.decryptProperties(reference);
    }
}
