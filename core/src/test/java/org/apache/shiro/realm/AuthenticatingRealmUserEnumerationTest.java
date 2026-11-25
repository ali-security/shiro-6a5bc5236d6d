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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.junit.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

/**
 * Regression tests for CVE-2026-23901: a login attempt for a non-existent account must perform the same credentials
 * matching (password hashing) work as a failed login attempt for an existing account, so that the response time does
 * not reveal whether or not an account exists (user enumeration via timing).
 */
public class AuthenticatingRealmUserEnumerationTest {

    private static final String USERNAME = "existing";
    private static final String PASSWORD = "secret";
    private static final String WRONG_PASSWORD = "wrong";
    private static final String UNKNOWN_USERNAME = "doesNotExist";
    private static final int ITERATIONS = 1024;

    @Test
    public void testHashedCredentialsMatcherHashesForUnknownUser() {
        CountingHashedCredentialsMatcher matcher = new CountingHashedCredentialsMatcher();
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.setCredentialsMatcher(matcher);
        realm.addAccount(USERNAME, new Sha256Hash(PASSWORD, null, ITERATIONS).toHex());

        // sanity check - the existing account can log in:
        assertNotNull(realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD)));

        matcher.hashCount.set(0);
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, WRONG_PASSWORD));
            fail("IncorrectCredentialsException expected for a wrong password");
        } catch (IncorrectCredentialsException expected) {
        }
        int existingUserHashes = matcher.hashCount.get();
        assertEquals(1, existingUserHashes);

        matcher.hashCount.set(0);
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken(UNKNOWN_USERNAME, WRONG_PASSWORD));
        assertNull(info);
        assertEquals("a non-existent account must cost as many password hashes as an existing one",
                existingUserHashes, matcher.hashCount.get());
        assertEquals("the same hash iteration count must be used for non-existent accounts",
                ITERATIONS, matcher.lastIterations.get());
    }

    @Test
    public void testPasswordMatcherHashesForUnknownUser() {
        CountingPasswordService passwordService = new CountingPasswordService();
        PasswordMatcher matcher = new PasswordMatcher();
        matcher.setPasswordService(passwordService);
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.setCredentialsMatcher(matcher);
        realm.addAccount(USERNAME, passwordService.encryptPassword(PASSWORD));

        // sanity check - the existing account can log in:
        assertNotNull(realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD)));

        passwordService.matchCount.set(0);
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, WRONG_PASSWORD));
            fail("IncorrectCredentialsException expected for a wrong password");
        } catch (IncorrectCredentialsException expected) {
        }
        int existingUserHashes = passwordService.matchCount.get();
        assertEquals(1, existingUserHashes);

        passwordService.matchCount.set(0);
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken(UNKNOWN_USERNAME, WRONG_PASSWORD));
        assertNull(info);
        assertEquals("a non-existent account must cost as many password hashes as an existing one",
                existingUserHashes, passwordService.matchCount.get());
        assertEquals("the same hash iteration count must be used for non-existent accounts",
                ITERATIONS, passwordService.lastIterations.get());

        // repeated attempts keep performing the same work:
        passwordService.matchCount.set(0);
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken(UNKNOWN_USERNAME + "2", PASSWORD)));
        assertEquals(existingUserHashes, passwordService.matchCount.get());
    }

    @Test
    public void testSimpleCredentialsMatcherComparesForUnknownUser() {
        CountingSimpleCredentialsMatcher matcher = new CountingSimpleCredentialsMatcher();
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.setCredentialsMatcher(matcher);
        realm.addAccount(USERNAME, PASSWORD);

        matcher.compareCount.set(0);
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, WRONG_PASSWORD));
            fail("IncorrectCredentialsException expected for a wrong password");
        } catch (IncorrectCredentialsException expected) {
        }
        int existingUserComparisons = matcher.compareCount.get();
        assertEquals(1, existingUserComparisons);

        matcher.compareCount.set(0);
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken(UNKNOWN_USERNAME, WRONG_PASSWORD)));
        assertEquals("a non-existent account must perform the same credentials comparison as an existing one",
                existingUserComparisons, matcher.compareCount.get());
    }

    @Test
    public void testUnknownUserIsNeverAuthenticated() {
        // whatever password is submitted, a non-existent account must never be returned nor throw:
        SimpleAccountRealm plainRealm = new SimpleAccountRealm();
        plainRealm.addAccount(USERNAME, PASSWORD);
        assertNull(plainRealm.getAuthenticationInfo(new UsernamePasswordToken(UNKNOWN_USERNAME, PASSWORD)));
        assertNull(plainRealm.getAuthenticationInfo(new UsernamePasswordToken(UNKNOWN_USERNAME, "")));
        assertNull(plainRealm.getAuthenticationInfo(new UsernamePasswordToken(UNKNOWN_USERNAME, (String) null)));

        // the allow-all matcher must not match its own simulated credentials (e.g. in multi-realm setups):
        SimpleAccountRealm allowAllRealm = new SimpleAccountRealm();
        allowAllRealm.setCredentialsMatcher(new AllowAllCredentialsMatcher());
        allowAllRealm.addAccount(USERNAME, PASSWORD);
        assertNotNull(allowAllRealm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, WRONG_PASSWORD)));
        assertNull(allowAllRealm.getAuthenticationInfo(new UsernamePasswordToken(UNKNOWN_USERNAME, PASSWORD)));

        PasswordMatcher passwordMatcher = new PasswordMatcher();
        passwordMatcher.setPasswordService(new CountingPasswordService());
        SimpleAccountRealm passwordRealm = new SimpleAccountRealm();
        passwordRealm.setCredentialsMatcher(passwordMatcher);
        assertNull(passwordRealm.getAuthenticationInfo(new UsernamePasswordToken(UNKNOWN_USERNAME, PASSWORD)));
        assertNull(passwordRealm.getAuthenticationInfo(new UsernamePasswordToken(UNKNOWN_USERNAME, (String) null)));
    }

    /**
     * Counts the number of times the submitted credentials are hashed.
     */
    private static class CountingHashedCredentialsMatcher extends HashedCredentialsMatcher {
        private final AtomicInteger hashCount = new AtomicInteger();
        private final AtomicInteger lastIterations = new AtomicInteger();

        CountingHashedCredentialsMatcher() {
            super(Sha256Hash.ALGORITHM_NAME);
            setHashIterations(ITERATIONS);
        }

        @Override
        protected Hash hashProvidedCredentials(Object credentials, Object salt, int hashIterations) {
            hashCount.incrementAndGet();
            lastIterations.set(hashIterations);
            return super.hashProvidedCredentials(credentials, salt, hashIterations);
        }
    }

    /**
     * Counts the number of times a submitted password is hashed and compared against a saved hash.
     */
    private static class CountingPasswordService extends DefaultPasswordService {
        private final AtomicInteger matchCount = new AtomicInteger();
        private final AtomicInteger lastIterations = new AtomicInteger();

        CountingPasswordService() {
            DefaultHashService hashService = new DefaultHashService();
            hashService.setHashAlgorithmName(Sha256Hash.ALGORITHM_NAME);
            hashService.setHashIterations(ITERATIONS);
            hashService.setGeneratePublicSalt(true);
            setHashService(hashService);
        }

        @Override
        public boolean passwordsMatch(Object plaintext, Hash saved) {
            matchCount.incrementAndGet();
            if (saved != null) {
                lastIterations.set(saved.getIterations());
            }
            return super.passwordsMatch(plaintext, saved);
        }
    }

    /**
     * Counts the number of credentials comparisons.
     */
    private static class CountingSimpleCredentialsMatcher extends SimpleCredentialsMatcher {
        private final AtomicInteger compareCount = new AtomicInteger();

        @Override
        protected boolean equals(Object tokenCredentials, Object accountCredentials) {
            compareCount.incrementAndGet();
            return super.equals(tokenCredentials, accountCredentials);
        }
    }
}
