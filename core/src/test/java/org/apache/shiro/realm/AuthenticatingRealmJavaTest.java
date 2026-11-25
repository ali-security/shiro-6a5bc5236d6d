/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.authc.credential.Sha256CredentialsMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.crypto.hash.Sha512Hash;
import org.apache.shiro.crypto.hash.format.Shiro1CryptFormat;
import org.junit.Test;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class AuthenticatingRealmJavaTest {

    /**
     * should create SHA-256 hash (the default PasswordService algorithm) when user does not exist
     */
    @Test
    public void testAuthenticatingRealmShouldCreateSha256HashWhenUserDoesNotExist() {
        // given
        CountingPasswordMatcher passwordMatcher = new CountingPasswordMatcher();
        AuthenticationToken token = new UsernamePasswordToken("username", "password".toCharArray());
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(passwordMatcher);

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(token);

        // then
        assertNull(info);
        assertEquals(1, passwordMatcher.simulatedCount.get());

        Hash simulatedHash = parseSimulatedCredentials(realm.authInfo);
        assertEquals(DefaultPasswordService.DEFAULT_HASH_ALGORITHM, simulatedHash.getAlgorithmName());
        assertEquals(DefaultPasswordService.DEFAULT_HASH_ITERATIONS, simulatedHash.getIterations());
    }

    /**
     * should create a hash using the configured PasswordService algorithm when user does not exist
     */
    @Test
    public void testAuthenticatingRealmShouldCreateConfiguredHashWhenUserDoesNotExist() {
        // given
        DefaultHashService sha512HashService = new DefaultHashService();
        sha512HashService.setHashAlgorithmName(Sha512Hash.ALGORITHM_NAME);
        sha512HashService.setHashIterations(1024);
        sha512HashService.setGeneratePublicSalt(true);
        DefaultPasswordService defaultPasswordService = new DefaultPasswordService();
        defaultPasswordService.setHashService(sha512HashService);
        CountingPasswordMatcher passwordMatcher = new CountingPasswordMatcher();
        passwordMatcher.setPasswordService(defaultPasswordService);

        AuthenticationToken token = new UsernamePasswordToken("username", "password".toCharArray());
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(passwordMatcher);

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(token);

        // then
        assertNull(info);
        assertEquals(1, passwordMatcher.simulatedCount.get());

        Hash simulatedHash = parseSimulatedCredentials(realm.authInfo);
        assertEquals(Sha512Hash.ALGORITHM_NAME, simulatedHash.getAlgorithmName());
        assertEquals(1024, simulatedHash.getIterations());
    }

    /**
     * should create the simulated credentials only once
     */
    @Test
    public void testSimulatedCredentialsAreCreatedOnlyOnce() {
        CountingSimpleCredentialsMatcher matcher = new CountingSimpleCredentialsMatcher();
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(matcher);

        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("user1", "password")));
        AuthenticationInfo first = realm.authInfo;
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("user2", "password")));

        assertNotNull(first);
        assertSame(first, realm.authInfo);
        assertEquals(1, matcher.simulatedCount.get());
        assertTrue("simulated credentials must be random bytes", first.getCredentials() instanceof byte[]);
    }

    /**
     * a HashedCredentialsMatcher (hex encoded stored credentials by default) must be able to check the simulated
     * credentials without failing.
     */
    @Test
    public void testHashedCredentialsMatcherSimulatedCredentials() {
        Sha256CredentialsMatcher matcher = new Sha256CredentialsMatcher();
        matcher.setHashIterations(1024);
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.setCredentialsMatcher(matcher);
        realm.addAccount("existing", new Sha256Hash("password", null, 1024).toHex());

        assertNotNull(realm.getAuthenticationInfo(new UsernamePasswordToken("existing", "password")));
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password")));
    }

    /**
     * should return null without failing when the CredentialsMatcher does not supply simulated credentials
     */
    @Test
    public void testCredentialsMatcherWithoutSimulatedCredentials() {
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(new CredentialsMatcher() {
            public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
                return true;
            }
        });

        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password")));
        assertNull(realm.authInfo);
    }

    /**
     * should return null without failing when no CredentialsMatcher is configured
     */
    @Test
    public void testNullCredentialsMatcher() {
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(null);

        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password")));
        assertNull(realm.authInfo);
    }

    /**
     * simulated credentials created by a previous CredentialsMatcher must not be used by a new one
     */
    @Test
    public void testSimulatedCredentialsAreDiscardedWhenCredentialsMatcherChanges() {
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(new SimpleCredentialsMatcher());
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password")));
        AuthenticationInfo simple = realm.authInfo;
        assertTrue(simple.getCredentials() instanceof byte[]);

        PasswordMatcher passwordMatcher = new PasswordMatcher();
        passwordMatcher.setPasswordService(createFastPasswordService());
        realm.setCredentialsMatcher(passwordMatcher);
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password")));

        assertNotSame(simple, realm.authInfo);
        assertNotNull(parseSimulatedCredentials(realm.authInfo));
    }

    private static Hash parseSimulatedCredentials(AuthenticationInfo info) {
        assertNotNull(info);
        Object simulatedCredentials = info.getCredentials();
        assertTrue("simulated credentials must be a formatted hash, like stored passwords",
                simulatedCredentials instanceof String);
        Hash hash = new Shiro1CryptFormat().parse((String) simulatedCredentials);
        assertNotNull(hash);
        return hash;
    }

    private static DefaultPasswordService createFastPasswordService() {
        DefaultHashService hashService = new DefaultHashService();
        hashService.setHashAlgorithmName(Sha256Hash.ALGORITHM_NAME);
        hashService.setHashIterations(1024);
        hashService.setGeneratePublicSalt(true);
        DefaultPasswordService passwordService = new DefaultPasswordService();
        passwordService.setHashService(hashService);
        return passwordService;
    }

    /**
     * Counts the number of simulated credentials creations.
     */
    static class CountingPasswordMatcher extends PasswordMatcher {
        private final AtomicInteger simulatedCount = new AtomicInteger();

        @Override
        public Optional<AuthenticationInfo> createSimulatedCredentials() {
            simulatedCount.incrementAndGet();
            return super.createSimulatedCredentials();
        }
    }

    /**
     * Counts the number of simulated credentials creations.
     */
    static class CountingSimpleCredentialsMatcher extends SimpleCredentialsMatcher {
        private final AtomicInteger simulatedCount = new AtomicInteger();

        @Override
        public Optional<AuthenticationInfo> createSimulatedCredentials() {
            simulatedCount.incrementAndGet();
            return super.createSimulatedCredentials();
        }
    }

    /**
     * For the test, it is important that this class returns {@code null} for
     * {@link AuthenticatingRealm#doGetAuthenticationInfo(AuthenticationToken)},
     * so that simulatedAuthenticationInfo is being created.
     */
    static class NullAuthenticatingRealm extends AuthenticatingRealm {

        /**
         * captured created authenticationInfo
         */
        private AuthenticationInfo authInfo;

        @Override
        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {
            return null;
        }

        /**
         * Captures the created authenticationInfo for tests.
         * @return see super method.
         */
        @Override
        AuthenticationInfo ensureSimulatedAuthenticationInfo() {
            final AuthenticationInfo authInfo1 = super.ensureSimulatedAuthenticationInfo();
            this.authInfo = authInfo1;
            return authInfo1;
        }
    }
}
