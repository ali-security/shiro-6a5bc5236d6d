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
package org.apache.shiro.mgt;

import org.apache.shiro.io.DefaultSerializer;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.junit.Test;

import java.time.Instant;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

/**
 * Test cases for the {@link AbstractRememberMeManager} implementation.
 */
public class AbstractRememberMeManagerTest {

    /**
     * Tests the {@link AbstractRememberMeManager#getRememberedPrincipals(SubjectContext)} method
     * implementation when the internal
     * {@link AbstractRememberMeManager#getRememberedSerializedIdentity(SubjectContext)} method
     * returns null or empty bytes.
     */
    @Test
    public void testGetRememberedPrincipalsWithEmptySerializedBytes() {
        AbstractRememberMeManager rmm = new DummyRememberMeManager();
        //Since the dummy's getRememberedSerializedIdentity implementation returns an empty byte
        //array, we should be ok:
        PrincipalCollection principals = rmm.getRememberedPrincipals(new DefaultSubjectContext());
        assertNull(principals);

        //try with a null return value too:
        rmm = new DummyRememberMeManager() {
            @Override
            protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
                return null;
            }
        };
        principals = rmm.getRememberedPrincipals(new DefaultSubjectContext());
        assertNull(principals);
    }

    /**
     * The remembered identity must carry the time at which it was created, so that its age can be verified when it is
     * presented again.
     */
    @Test
    public void testRememberedIdentityContainsCreationTime() {
        Instant created = Instant.parse("2021-01-01T00:00:00Z");
        ExpiringRememberMeManager rmm = new ExpiringRememberMeManager(created, 60);
        PrincipalCollection principals = new SimplePrincipalCollection("user", "test");

        rmm.rememberIdentity(null, principals);
        assertNotNull(rmm.remembered);

        AbstractRememberMeManager.RememberedIdentity identity = rmm.deserialize(rmm.decrypt(rmm.remembered));
        assertEquals(principals, identity.principals());
        assertEquals(created, identity.creationTime());

        PrincipalCollection remembered = rmm.getRememberedPrincipals(new DefaultSubjectContext());
        assertEquals(principals, remembered);
    }

    /**
     * A captured remember me value replayed after its maximum age has passed must not be accepted.
     */
    @Test
    public void testExpiredRememberedIdentityIsRejected() {
        Instant created = Instant.parse("2021-01-01T00:00:00Z");
        ExpiringRememberMeManager rmm = new ExpiringRememberMeManager(created, 60);
        PrincipalCollection principals = new SimplePrincipalCollection("user", "test");
        rmm.rememberIdentity(null, principals);
        byte[] captured = rmm.remembered;

        //still within the maximum age:
        rmm.clock = created.plusSeconds(60);
        assertEquals(principals, rmm.getRememberedPrincipals(new DefaultSubjectContext()));

        //replayed after the maximum age:
        rmm.clock = created.plusSeconds(61);
        rmm.remembered = captured;
        assertNull(rmm.getRememberedPrincipals(new DefaultSubjectContext()));

        //long after the maximum age:
        rmm.clock = created.plusSeconds(60L * 60 * 24 * 365);
        rmm.remembered = captured;
        assertNull(rmm.getRememberedPrincipals(new DefaultSubjectContext()));
    }

    /**
     * A remembered identity in the previous format (a bare {@code PrincipalCollection} without a creation time) cannot
     * be checked for expiration, so it must not be accepted and must be forgotten.
     */
    @Test
    public void testRememberedIdentityWithoutCreationTimeIsRejected() {
        ExpiringRememberMeManager rmm = new ExpiringRememberMeManager(Instant.parse("2021-01-01T00:00:00Z"), 60);
        PrincipalCollection principals = new SimplePrincipalCollection("user", "test");
        rmm.remembered = rmm.encrypt(new DefaultSerializer<PrincipalCollection>().serialize(principals));

        try {
            rmm.getRememberedPrincipals(new DefaultSubjectContext());
            fail("A remembered identity without a creation time must not be accepted");
        } catch (RuntimeException expected) {
            assertEquals(1, rmm.forgetCount);
        }
    }

    /**
     * Remember me manager that keeps the remembered identity in memory, with a settable clock and a maximum age
     * (in seconds) that is enforced on the server side.
     */
    private static class ExpiringRememberMeManager extends AbstractRememberMeManager {

        private Instant clock;

        private final long maxAge;

        private byte[] remembered;

        private int forgetCount;

        ExpiringRememberMeManager(Instant clock, long maxAge) {
            this.clock = clock;
            this.maxAge = maxAge;
        }

        @Override
        protected Instant now() {
            return clock;
        }

        @Override
        protected PrincipalCollection checkExpiration(RememberedIdentity identity) {
            if (maxAge >= 0 && now().isAfter(identity.creationTime().plusSeconds(maxAge))) {
                return null;
            }
            return super.checkExpiration(identity);
        }

        public void forgetIdentity(SubjectContext subjectContext) {
            forgetCount++;
            remembered = null;
        }

        @Override
        protected void forgetIdentity(Subject subject) {
            remembered = null;
        }

        @Override
        protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
            remembered = serialized;
        }

        @Override
        protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
            return remembered;
        }
    }

    private static class DummyRememberMeManager extends AbstractRememberMeManager {
        public void forgetIdentity(SubjectContext subjectContext) {
            //do nothing
        }

        @Override
        protected void forgetIdentity(Subject subject) {
        }

        @Override
        protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
        }

        @Override
        protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
            return new byte[0];
        }
    }
}
