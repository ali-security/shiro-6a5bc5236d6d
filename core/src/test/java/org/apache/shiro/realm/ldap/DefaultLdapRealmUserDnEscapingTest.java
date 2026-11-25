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

import org.apache.shiro.authc.UsernamePasswordToken;
import org.easymock.Capture;
import org.junit.Before;
import org.junit.Test;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.isA;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

/**
 * Verifies that {@link DefaultLdapRealm} escapes RFC 2253 special characters in the submitted principal before
 * substituting it into the configured {@code userDnTemplate}, so a user-supplied username can never alter the
 * structure of the User DN used for the LDAP bind (LDAP DN injection, CVE-2026-49268).
 */
public class DefaultLdapRealmUserDnEscapingTest {

    private static final String TEMPLATE = "uid={0},ou=users,dc=mycompany,dc=com";
    private static final String TEMPLATE_SUFFIX = "ou=users,dc=mycompany,dc=com";

    private static final String[] MALICIOUS_PRINCIPALS = {
            // RDN separator: would move the bind to a different subtree
            "admin,ou=admins",
            "admin,ou=admins,dc=mycompany,dc=com",
            // legacy RFC 1779 RDN separator
            "admin;ou=admins",
            // multi-valued RDN: would add an extra attribute assertion to the user's RDN
            "jsmith+cn=admin",
            // attribute type/value separator and other special characters
            "a=b",
            "jsmith\\,ou=admins",
            "\"jsmith\"",
            "<jsmith>",
            "#jsmith",
            " jsmith ",
            "x)(uid=*"
    };

    private DefaultLdapRealm realm;

    @Before
    public void setUp() {
        realm = new DefaultLdapRealm();
        realm.setUserDnTemplate(TEMPLATE);
    }

    @Test
    public void testTemplateIsUnchanged() {
        assertEquals(TEMPLATE, realm.getUserDnTemplate());
    }

    @Test
    public void testSimplePrincipalIsUnchanged() {
        assertEquals("uid=jsmith,ou=users,dc=mycompany,dc=com", realm.getUserDn("jsmith"));
    }

    @Test
    public void testGetUserDnEscapesDnSpecialCharacters() throws Exception {
        for (String principal : MALICIOUS_PRINCIPALS) {
            assertUserDnStructure(principal, realm.getUserDn(principal));
        }
    }

    @Test
    public void testAuthenticationBindDnCannotBeInjected() throws Exception {
        for (String principal : MALICIOUS_PRINCIPALS) {
            LdapContextFactory factory = createMock(LdapContextFactory.class);
            Capture<Object> boundPrincipal = Capture.newInstance();
            expect(factory.getLdapContext(capture(boundPrincipal), isA(Object.class)))
                    .andReturn(createNiceMock(LdapContext.class));
            replay(factory);

            realm.setContextFactory(factory);
            realm.getAuthenticationInfo(new UsernamePasswordToken(principal, "secret"));
            verify(factory);

            assertUserDnStructure(principal, (String) boundPrincipal.getValue());
        }
    }

    private static void assertUserDnStructure(String principal, String userDn) throws NamingException {
        LdapName dn = new LdapName(userDn);
        // uid=<principal>, ou=users, dc=mycompany, dc=com - no injected RDNs
        assertEquals("Unexpected RDN count for principal [" + principal + "]: " + userDn, 4, dn.size());
        assertEquals("Template suffix altered for principal [" + principal + "]: " + userDn,
                new LdapName(TEMPLATE_SUFFIX), dn.getPrefix(3));

        Rdn userRdn = dn.getRdn(dn.size() - 1);
        // single-valued RDN - no injected '+' attribute assertions
        assertEquals("Multi-valued RDN for principal [" + principal + "]: " + userDn, 1, userRdn.size());
        assertEquals("uid", userRdn.getType());
        assertEquals(principal, userRdn.getValue());
    }
}
