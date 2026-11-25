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
package org.apache.shiro.authc.credential;

import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Verifies that an empty or missing stored credential never matches a submitted credential.
 */
public class SimpleCredentialsMatcherTest {

    @Test
    public void testMatchingPassword() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo("user", "secret", "realm");
        assertTrue(matcher.doCredentialsMatch(new UsernamePasswordToken("user", "secret"), info));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", "wrong"), info));
    }

    @Test
    public void testEmptyStoredCredentialNeverMatches() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo("user", "", "realm");
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", ""), info));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", new char[0]), info));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", "secret"), info));
    }

    @Test
    public void testEmptyByteArrayStoredCredentialNeverMatches() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo("user", new byte[0], "realm");
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", ""), info));
    }

    @Test
    public void testNullStoredCredentialNeverMatches() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo("user", null, "realm");
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", (char[]) null), info));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", ""), info));
    }
}
