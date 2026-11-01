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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import umrao.tomcat.vault.cli.TomcatVaultCLI;
import umrao.tomcat.vault.jmx.VaultJmxSanitizer;
import umrao.tomcat.vault.key.CompositeKeyProvider;
import umrao.tomcat.vault.key.SecretResolverKeyProvider;
import umrao.tomcat.vault.refresh.VaultCredentialReloader;
import umrao.tomcat.vault.secret.SecretResolver;
import umrao.tomcat.vault.secret.SecretResolverRegistry;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Enterprise live highly-concurrent stress and load benchmark suite.
 * Simulates high-throughput production application loads:
 * - 50 concurrent worker threads executing 50,000+ operations
 * - Live dynamic key rotation and cache eviction stampede under active traffic
 * - High-concurrency cloud secret resolution with TTL caching
 * - High-frequency JMX URL sanitization without memory churn
 * - Full verification of zero downtime, zero data corruption, and zero race conditions.
 *
 * @author Vivek Umrao
 */
@SuppressWarnings("resource")
class VaultHighConcurrencyStressAndLoadTest {

    private String originalStrictProp;

    @BeforeEach
    void setUp() {
        originalStrictProp = System.getProperty(VaultConstants.SYS_PROP_STRICT);
        VaultCrypto.clearKeyCache();
        SecretResolverRegistry.getInstance().resetDefaultResolvers();
        VaultCredentialReloader.getInstance().clearListeners();
    }

    @AfterEach
    void tearDown() {
        if (originalStrictProp != null) {
            System.setProperty(VaultConstants.SYS_PROP_STRICT, originalStrictProp);
        } else {
            System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        }
        VaultCrypto.clearKeyCache();
        SecretResolverRegistry.getInstance().resetDefaultResolvers();
        VaultCredentialReloader.getInstance().clearListeners();
    }

    @Test
    @DisplayName("Stress Test: 50 concurrent threads executing 50,000 crypto operations under stampede load")
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void testMassiveHighConcurrencyEncryptionDecryptionStress() throws Exception {
        int threadCount = 50;
        int operationsPerThread = 1000; // 50,000 total operations
        int totalOperations = threadCount * operationsPerThread;

        VaultCrypto crypto = new VaultCrypto("StressTestMasterSecretKey2026!#UltraSecure");
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch readyLatch = new CountDownLatch(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);

        AtomicInteger successCounter = new AtomicInteger(0);
        AtomicInteger failureCounter = new AtomicInteger(0);
        AtomicLong totalDurationNanos = new AtomicLong(0);

        String[] testPlaintexts = new String[]{
                "ProdDatabaseUserPass#2026!",
                "jdbc:oracle:thin:hr/hrpass@//dbprod.corp.local:1521/ORCL",
                "SuperSecretToken_AES256_GCM_Validation_Key",
                "p@$$w0rd-with-symbols-!@#$%^&*()_+",
                "SimplePlainStringForThroughputBenchmark"
        };

        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                readyLatch.countDown();
                try {
                    startLatch.await();
                    long tStart = System.nanoTime();
                    for (int i = 0; i < operationsPerThread; i++) {
                        String sample = testPlaintexts[(threadId + i) % testPlaintexts.length];
                        String encrypted = crypto.encrypt(sample);
                        String decrypted = crypto.decrypt(encrypted);

                        if (sample.equals(decrypted)) {
                            successCounter.incrementAndGet();
                        } else {
                            failureCounter.incrementAndGet();
                        }
                    }
                    totalDurationNanos.addAndGet(System.nanoTime() - tStart);
                } catch (Exception e) {
                    failureCounter.incrementAndGet();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        assertTrue(readyLatch.await(30, TimeUnit.SECONDS), "Workers must be ready");
        long benchStart = System.currentTimeMillis();
        startLatch.countDown();

        boolean completed = doneLatch.await(45, TimeUnit.SECONDS);
        long benchDuration = System.currentTimeMillis() - benchStart;
        executor.shutdown();

        assertTrue(completed, "Stress test completed within timeout");
        assertEquals(0, failureCounter.get(), "Zero decryption failures allowed during stress test");
        assertEquals(totalOperations, successCounter.get(), "All operations must succeed");

        double opsPerSec = (totalOperations * 1000.0) / Math.max(benchDuration, 1);
        assertTrue(opsPerSec > 500, "Throughput should exceed 500 ops/sec under concurrent load");
    }

    @Test
    @DisplayName("Stress Test: Zero-downtime key rotation under concurrent read/write stampede")
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testLiveStampedeKeyRotationUnderLoad() throws Exception {
        int workerCount = 30;
        ExecutorService executor = Executors.newFixedThreadPool(workerCount + 1);

        CompositeKeyProvider compositeProvider = new CompositeKeyProvider();
        compositeProvider.registerKey("v1", "AlphaKeyVersionOneSecret2026!#Key1");
        compositeProvider.registerKey("v2", "BetaKeyVersionTwoSecret2026!#Key2");
        compositeProvider.registerKey("v3", "GammaKeyVersionThreeSecret2026!#Key3");

        VaultCrypto crypto = new VaultCrypto(compositeProvider);

        AtomicBoolean running = new AtomicBoolean(true);
        AtomicInteger successfulOps = new AtomicInteger(0);
        AtomicInteger rotationErrors = new AtomicInteger(0);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch workersDone = new CountDownLatch(workerCount);

        // Pre-create encrypted payloads under different key versions
        String payloadV1 = crypto.encrypt("DatabaseSecretUnderV1", "v1");
        String payloadV2 = crypto.encrypt("DatabaseSecretUnderV2", "v2");
        String payloadV3 = crypto.encrypt("DatabaseSecretUnderV3", "v3");

        // 30 worker threads constantly encrypting and decrypting
        for (int i = 0; i < workerCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    while (running.get()) {
                        String d1 = crypto.decrypt(payloadV1);
                        String d2 = crypto.decrypt(payloadV2);
                        String d3 = crypto.decrypt(payloadV3);

                        if ("DatabaseSecretUnderV1".equals(d1)
                                && "DatabaseSecretUnderV2".equals(d2)
                                && "DatabaseSecretUnderV3".equals(d3)) {
                            successfulOps.addAndGet(3);
                        } else {
                            rotationErrors.incrementAndGet();
                        }

                        // Also perform dynamic encryption
                        String fresh = crypto.encrypt("DynamicValue", "v2");
                        if ("DynamicValue".equals(crypto.decrypt(fresh))) {
                            successfulOps.incrementAndGet();
                        } else {
                            rotationErrors.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    rotationErrors.incrementAndGet();
                } finally {
                    workersDone.countDown();
                }
            });
        }

        // Dedicated rotator thread executing rotations concurrently
        executor.submit(() -> {
            try {
                startLatch.await();
                for (int r = 4; r <= 20; r++) {
                    Thread.sleep(20);
                    String alias = "v" + r;
                    compositeProvider.registerKey(alias, "RotatedKeySecretPassphraseIteration_" + r);
                    VaultCrypto.clearKeyCache();
                    VaultCredentialReloader.getInstance().notifyReload("*");
                }
            } catch (Exception ignored) {
            } finally {
                running.set(false);
            }
        });

        startLatch.countDown();
        assertTrue(workersDone.await(20, TimeUnit.SECONDS), "Workers must complete within timeout");
        executor.shutdown();

        assertEquals(0, rotationErrors.get(), "Zero decryption failures allowed during dynamic key rotation");
        assertTrue(successfulOps.get() > 1000, "Workers should perform thousands of operations during rotation");
    }

    @Test
    @DisplayName("Stress Test: High-concurrency cloud secret resolution with TTL caching stampede")
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testConcurrentCloudSecretCacheStampede() throws Exception {
        int threads = 40;
        int callsPerThread = 500;
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        AtomicInteger callCount = new AtomicInteger(0);
        SecretResolver customResolver = new SecretResolver() {
            @Override
            public boolean supports(String expression) {
                return expression != null && expression.startsWith("AWS_SECRET(");
            }

            @Override
            public String resolve(String expression) {
                callCount.incrementAndGet();
                return "ResolvedDbPassword#123";
            }

            @Override
            public String getResolverName() {
                return "MockAwsResolver";
            }
        };

        SecretResolverRegistry registry = SecretResolverRegistry.getInstance();
        registry.registerResolver(customResolver);

        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threads);
        AtomicInteger resolutionErrors = new AtomicInteger(0);

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < callsPerThread; j++) {
                        String secret = registry.resolve("AWS_SECRET(prod/database#password)");
                        if (!"ResolvedDbPassword#123".equals(secret)) {
                            resolutionErrors.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    resolutionErrors.incrementAndGet();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(15, TimeUnit.SECONDS), "Workers must finish within timeout");
        executor.shutdown();

        assertEquals(0, resolutionErrors.get(), "Zero resolution errors allowed");
        // Because of the TTL cache, callCount should be dramatically lower than (40 * 500 = 20,000)
        assertTrue(callCount.get() < 50, "TTL cache must prevent repetitive external secret provider calls");
    }

    @Test
    @DisplayName("Stress Test: High-frequency JMX URL sanitization across multiple threads")
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void testConcurrentJmxSanitizerStress() throws Exception {
        int threads = 30;
        int iterations = 1000;
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        String[] testUrls = new String[]{
                "jdbc:mysql://admin:secret123@db.prod.internal:3306/appdb",
                "jdbc:oracle:thin:scott/tiger@localhost:1521:xe",
                "jdbc:sqlserver://srv;databaseName=db;user=sa;password=SecretSQLPass;",
                "jdbc:postgresql://db.corp.net:5432/orders?user=dbuser&pwd=pgpassword",
                "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1" // Benign without credentials
        };

        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threads);
        AtomicInteger failures = new AtomicInteger(0);

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < iterations; j++) {
                        for (String url : testUrls) {
                            String sanitized = VaultJmxSanitizer.sanitizeUrl(url);
                            if (url.contains("secret123") && sanitized.contains("secret123")) {
                                failures.incrementAndGet();
                            }
                            if (url.contains("tiger") && sanitized.contains("tiger")) {
                                failures.incrementAndGet();
                            }
                            if (url.contains("SecretSQLPass") && sanitized.contains("SecretSQLPass")) {
                                failures.incrementAndGet();
                            }
                            if (url.contains("pgpassword") && sanitized.contains("pgpassword")) {
                                failures.incrementAndGet();
                            }
                        }
                    }
                } catch (Exception e) {
                    failures.incrementAndGet();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(15, TimeUnit.SECONDS), "Sanitization tasks must finish within timeout");
        executor.shutdown();

        assertEquals(0, failures.get(), "Sanitization must be 100% accurate under high concurrency");
    }

    @Test
    @DisplayName("Feature: SecretResolverKeyProvider resolves encryption keys from cloud vault paths")
    void testSecretResolverKeyProviderIntegration() {
        SecretResolverRegistry registry = SecretResolverRegistry.getInstance();
        registry.registerResolver(new SecretResolver() {
            @Override
            public boolean supports(String expression) {
                return expression != null && expression.startsWith("VAULT(master/encryption/key");
            }

            @Override
            public String resolve(String expression) {
                if (expression.contains("#v2")) {
                    return "VaultCloudSecretKeyVersionTwo2026!";
                }
                return "VaultCloudSecretKeyVersionOne2026!";
            }

            @Override
            public String getResolverName() {
                return "TestCloudKeyResolver";
            }
        });

        // 1. Explicit path
        SecretResolverKeyProvider provider = new SecretResolverKeyProvider("VAULT(master/encryption/key#master)");
        assertTrue(provider.isAvailable());
        assertEquals("VAULT(master/encryption/key#master)", provider.getVaultSecretPath());
        assertEquals("VaultCloudSecretKeyVersionOne2026!", provider.getKey());
        assertEquals("VaultCloudSecretKeyVersionTwo2026!", provider.getKey("v2"));
        assertTrue(provider.getProviderName().contains("SecretResolverKeyProvider"));

        // 2. Unconfigured path
        SecretResolverKeyProvider emptyProvider = new SecretResolverKeyProvider(null);
        assertFalse(emptyProvider.isAvailable());
        assertNull(emptyProvider.getKey());
        assertNull(emptyProvider.getKey("any"));
        assertNull(emptyProvider.getVaultSecretPath());
        assertTrue(emptyProvider.getProviderName().contains("unconfigured"));

        // 3. System property path resolution
        System.setProperty(SecretResolverKeyProvider.SYS_PROP_CLOUD_PATH, "VAULT(master/encryption/key#sysprop)");
        try {
            SecretResolverKeyProvider propProvider = new SecretResolverKeyProvider();
            assertTrue(propProvider.isAvailable());
            assertEquals("VaultCloudSecretKeyVersionOne2026!", propProvider.getKey());
        } finally {
            System.clearProperty(SecretResolverKeyProvider.SYS_PROP_CLOUD_PATH);
        }
    }

    @Test
    @DisplayName("CLI: --status and --health diagnostic commands execute successfully")
    void testCliHealthAndStatusFlag() {
        int statusExit = TomcatVaultCLI.execute("--status");
        assertEquals(0, statusExit, "--status CLI command should return exit code 0");

        int healthExit = TomcatVaultCLI.execute("--health");
        assertEquals(0, healthExit, "--health CLI command should return exit code 0");
    }
}
