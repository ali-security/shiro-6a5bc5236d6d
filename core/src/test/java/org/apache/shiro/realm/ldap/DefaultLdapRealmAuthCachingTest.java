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
package org.apache.shiro.realm.ldap;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.junit.Test;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Regression tests for CVE-2026-129349: when authentication caching is enabled, a cached
 * {@link org.apache.shiro.authc.AuthenticationInfo AuthenticationInfo} skips the LDAP bind, so the submitted
 * credentials must still be verified against the cached credentials.  Before the fix the realm installed an
 * {@link org.apache.shiro.authc.credential.AllowAllCredentialsMatcher AllowAllCredentialsMatcher} by default, which
 * allowed any password to log in once the user had authenticated successfully a single time.
 */
public class DefaultLdapRealmAuthCachingTest {

    private static final String USERNAME = "jsmith";
    private static final String USER_DN = "uid=jsmith,ou=users,dc=mycompany,dc=com";
    private static final String PASSWORD = "secret";
    private static final String WRONG_PASSWORD = "wrong";

    @Test
    public void testCachedAuthenticationRejectsWrongPassword() throws NamingException {
        assertCachedAuthenticationRejectsWrongPassword(new DefaultLdapRealm());
    }

    @Test
    public void testCachedAuthenticationRejectsWrongPasswordJndiLdapRealm() throws NamingException {
        assertCachedAuthenticationRejectsWrongPassword(new JndiLdapRealm());
    }

    @Test
    public void testCachedAuthenticationRejectsWrongPasswordForSecondUser() throws NamingException {
        DefaultLdapRealm realm = createCachingRealm(new DefaultLdapRealm());
        LdapContextFactory factory = createStrictMock(LdapContextFactory.class);
        realm.setContextFactory(factory);

        // two different users authenticate successfully against LDAP, each exactly once:
        expect(factory.getLdapContext(eq(USER_DN), aryEq(PASSWORD.toCharArray())))
                .andReturn(createNiceMock(LdapContext.class));
        expect(factory.getLdapContext(eq("uid=bob,ou=users,dc=mycompany,dc=com"), aryEq("bobsecret".toCharArray())))
                .andReturn(createNiceMock(LdapContext.class));
        replay(factory);

        assertNotNull(realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD)));
        assertNotNull(realm.getAuthenticationInfo(new UsernamePasswordToken("bob", "bobsecret")));

        // neither user's cached entry may be reused with another user's (valid) password:
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, "bobsecret"));
            fail("a cached authentication must not accept another user's password");
        } catch (IncorrectCredentialsException expected) {
        }
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken("bob", PASSWORD));
            fail("a cached authentication must not accept another user's password");
        } catch (IncorrectCredentialsException expected) {
        }

        verify(factory);
    }

    private void assertCachedAuthenticationRejectsWrongPassword(DefaultLdapRealm realm) throws NamingException {
        createCachingRealm(realm);
        LdapContextFactory factory = createStrictMock(LdapContextFactory.class);
        realm.setContextFactory(factory);

        // the LDAP directory is contacted exactly once, for the first (successful) login only:
        expect(factory.getLdapContext(eq(USER_DN), aryEq(PASSWORD.toCharArray())))
                .andReturn(createNiceMock(LdapContext.class));
        replay(factory);

        // first login binds against LDAP and caches the AuthenticationInfo:
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD));
        assertNotNull(info);
        assertEquals(USERNAME, info.getPrincipals().getPrimaryPrincipal());

        // second login with a wrong password is served from the cache and must fail credentials matching:
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, WRONG_PASSWORD));
            fail("a cached authentication must not accept a wrong password");
        } catch (IncorrectCredentialsException expected) {
        }

        // an empty password must not be accepted either:
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, ""));
            fail("a cached authentication must not accept an empty password");
        } catch (IncorrectCredentialsException expected) {
        }

        // the correct password is still accepted from the cache (no additional LDAP bind):
        assertNotNull(realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD)));

        verify(factory);
    }

    private static DefaultLdapRealm createCachingRealm(DefaultLdapRealm realm) {
        realm.setUserDnTemplate("uid={0},ou=users,dc=mycompany,dc=com");
        realm.setCacheManager(new MemoryConstrainedCacheManager());
        realm.setAuthenticationCachingEnabled(true);
        assertTrue(realm.isAuthenticationCachingEnabled());
        return realm;
    }
}
