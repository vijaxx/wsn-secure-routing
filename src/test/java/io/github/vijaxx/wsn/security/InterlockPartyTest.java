package io.github.vijaxx.wsn.security;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Exercises the Interlock Protocol handshake, including the MITM-detection guarantees
 * documented on {@link InterlockParty}. Each test manipulates the wire-level messages
 * exchanged between two {@link InterlockParty} instances to play the role of an
 * adversary, which is the standard way to unit-test a two-party cryptographic protocol
 * without standing up real network sockets.
 */
class InterlockPartyTest {

    private final CryptoEngine engine = new CryptoEngine(2024L);
    private final DeploymentAuthority ca = new DeploymentAuthority(engine);

    private InterlockParty party(int id) {
        return new InterlockParty(engine, ca.provision(id));
    }

    /** Runs the honest 4-message exchange between two already-credentialed parties. */
    private void runHandshake(InterlockParty a, InterlockParty b) {
        a.receivePeerCredential(b.id(), CryptoEngine.encodePublicKey(b.publicKey()), b.certificate());
        b.receivePeerCredential(a.id(), CryptoEngine.encodePublicKey(a.publicKey()), a.certificate());

        byte[] aFirst = a.produceFirstHalf();
        byte[] aCommit = a.commitment();
        byte[] bFirst = b.produceFirstHalf();
        byte[] bCommit = b.commitment();

        b.receiveFirstHalf(aFirst, aCommit);
        a.receiveFirstHalf(bFirst, bCommit);

        byte[] aSecond = a.produceSecondHalf();
        byte[] bSecond = b.produceSecondHalf();

        b.receiveSecondHalf(aSecond);
        a.receiveSecondHalf(bSecond);
    }

    @Test
    void honestExchangeDerivesMatchingSessionKeys() {
        InterlockParty a = party(1);
        InterlockParty b = party(2);
        runHandshake(a, b);
        assertNotNull(a.sessionKey());
        assertNotNull(b.sessionKey());
        assertArrayEquals(a.sessionKey().getEncoded(), b.sessionKey().getEncoded());
    }

    @Test
    void sessionKeyIsIndependentOfWhichPartyIsIdentifiedFirst() {
        // node ids on both sides of the ascending-order convention
        InterlockParty a = party(10);
        InterlockParty b = party(3);
        runHandshake(a, b);
        assertArrayEquals(a.sessionKey().getEncoded(), b.sessionKey().getEncoded());
    }

    @Test
    void keySubstitutionMitmIsBlockedByCertificateCheck() {
        // Mallory holds her own valid, CA-issued credential (id 999) but tries to present
        // herself to B as node A (id 1) so she can terminate A's leg of the exchange.
        InterlockParty victimA = party(1);
        InterlockParty mallory = party(999);
        InterlockParty b = party(2);

        InterlockException ex = assertThrows(InterlockException.class, () ->
                b.receivePeerCredential(victimA.id(),
                        CryptoEngine.encodePublicKey(mallory.publicKey()), mallory.certificate()));
        assertEquals(InterlockException.Reason.BAD_CERTIFICATE, ex.reason());
    }

    @Test
    void relayWithoutTheDestinationPrivateKeyCannotDecrypt() {
        // A genuinely completes the credential + first-half + second-half exchange
        // intending to talk to B. An on-path relay who captures every byte on the wire
        // but is not B (does not hold B's private key) cannot complete B's side of the
        // handshake: the RSA-wrapped session key was sealed to B's public key.
        InterlockParty a = party(1);
        InterlockParty b = party(2);
        InterlockParty relay = party(777); // has its own, different, private key

        a.receivePeerCredential(b.id(), CryptoEngine.encodePublicKey(b.publicKey()), b.certificate());
        byte[] aFirst = a.produceFirstHalf();
        byte[] aCommit = a.commitment();

        // relay pretends to be "B" from A's perspective, but only has its own key material
        relay.receivePeerCredential(a.id(), CryptoEngine.encodePublicKey(a.publicKey()), a.certificate());
        relay.receiveFirstHalf(aFirst, aCommit);
        byte[] relayFirst = relay.produceFirstHalf();
        byte[] relayCommit = relay.commitment();
        a.receiveFirstHalf(relayFirst, relayCommit); // satisfies A's own interlock ordering rule

        byte[] aSecond = a.produceSecondHalf();

        assertThrows(InterlockException.class, () -> relay.receiveSecondHalf(aSecond));
    }

    @Test
    void tamperedSecondHalfFailsCommitmentCheck() {
        InterlockParty a = party(1);
        InterlockParty b = party(2);
        a.receivePeerCredential(b.id(), CryptoEngine.encodePublicKey(b.publicKey()), b.certificate());
        b.receivePeerCredential(a.id(), CryptoEngine.encodePublicKey(a.publicKey()), a.certificate());

        byte[] aFirst = a.produceFirstHalf();
        byte[] aCommit = a.commitment();
        byte[] bFirst = b.produceFirstHalf();
        byte[] bCommit = b.commitment();
        b.receiveFirstHalf(aFirst, aCommit);
        a.receiveFirstHalf(bFirst, bCommit);

        byte[] aSecond = a.produceSecondHalf();
        aSecond[0] ^= 0x7F; // flip bits: simulates an on-path tamper of the final message

        InterlockException ex = assertThrows(InterlockException.class, () -> b.receiveSecondHalf(aSecond));
        assertEquals(InterlockException.Reason.COMMITMENT_MISMATCH, ex.reason());
    }

    @Test
    void secondHalfCannotBeReleasedBeforePeersFirstHalfArrives() {
        InterlockParty a = party(1);
        InterlockParty b = party(2);
        a.receivePeerCredential(b.id(), CryptoEngine.encodePublicKey(b.publicKey()), b.certificate());
        a.produceFirstHalf();
        InterlockException ex = assertThrows(InterlockException.class, a::produceSecondHalf);
        assertEquals(InterlockException.Reason.PROTOCOL_ORDER, ex.reason());
    }

    @Test
    void firstHalfCannotBeProducedBeforePeerCredentialIsRegistered() {
        InterlockParty a = party(1);
        InterlockException ex = assertThrows(InterlockException.class, a::produceFirstHalf);
        assertEquals(InterlockException.Reason.PROTOCOL_ORDER, ex.reason());
    }

    @Test
    void replayedHandshakeIsRejectedBySharedNonceCache() {
        NonceCache shared = new NonceCache(64);
        NodeCredential credA = ca.provision(1);
        NodeCredential credB = ca.provision(2); // b's real, long-term credential

        InterlockParty a1 = new InterlockParty(engine, credA, true, shared);
        InterlockParty b1 = new InterlockParty(engine, credB, true, shared);
        a1.receivePeerCredential(b1.id(), CryptoEngine.encodePublicKey(b1.publicKey()), b1.certificate());
        b1.receivePeerCredential(a1.id(), CryptoEngine.encodePublicKey(a1.publicKey()), a1.certificate());

        byte[] aFirst = a1.produceFirstHalf();
        byte[] aCommit = a1.commitment();
        byte[] bFirst = b1.produceFirstHalf();
        byte[] bCommit = b1.commitment();
        b1.receiveFirstHalf(aFirst, aCommit);
        a1.receiveFirstHalf(bFirst, bCommit);
        byte[] aSecond = a1.produceSecondHalf();
        b1.produceSecondHalf();
        b1.receiveSecondHalf(aSecond); // consumes A's nonce in the shared cache

        // A second, independent session at B (same long-term credential and private key,
        // as if B is processing a fresh connection) that happens to receive the exact
        // same message bytes -- e.g. an attacker recording and re-injecting a captured
        // handshake -- must be rejected even though decryption, the commitment, and the
        // signature all check out perfectly.
        InterlockParty b2 = new InterlockParty(engine, credB, true, shared);
        b2.receivePeerCredential(1, CryptoEngine.encodePublicKey(a1.publicKey()), a1.certificate());
        byte[] aFirstAgain = Arrays.copyOf(aFirst, aFirst.length);
        b2.receiveFirstHalf(aFirstAgain, aCommit);
        InterlockException ex = assertThrows(InterlockException.class, () -> b2.receiveSecondHalf(aSecond));
        assertEquals(InterlockException.Reason.REPLAY, ex.reason());
    }

    @Test
    void identityClaimedInsideBlobMustMatchTheRegisteredPeer() {
        // B registers node A (id 1) as the peer it intends to talk to. But the bytes
        // that actually arrive were produced by node C (id 3) -- e.g. the underlying
        // transport silently connected B to the wrong party. C is a legitimate,
        // certified node and correctly encrypts/signs its own genuine message to B, so
        // decryption succeeds; only the claimed identity inside the payload is wrong.
        InterlockParty b = party(2);
        InterlockParty c = party(3);
        NodeCredential credA = ca.provision(1);

        b.receivePeerCredential(1, CryptoEngine.encodePublicKey(credA.publicKey()), credA.certificate());
        c.receivePeerCredential(b.id(), CryptoEngine.encodePublicKey(b.publicKey()), b.certificate());

        byte[] cFirst = c.produceFirstHalf();
        byte[] cCommit = c.commitment();
        b.receiveFirstHalf(cFirst, cCommit);

        // The interlock ordering rule (second half withheld until the peer's first half
        // arrives) applies regardless of who the traffic is actually from, so c must
        // still see a first half before releasing its second -- here it is b's, sent as
        // part of c's own genuine (if misdirected) session.
        byte[] bFirst = b.produceFirstHalf();
        byte[] bCommit = b.commitment();
        c.receiveFirstHalf(bFirst, bCommit);
        byte[] cSecond = c.produceSecondHalf();

        InterlockException ex = assertThrows(InterlockException.class, () -> b.receiveSecondHalf(cSecond));
        assertEquals(InterlockException.Reason.IDENTITY_MISMATCH, ex.reason());
    }

    @Test
    void keyViewMismatchDetectsASubstitutedPeerKeyInUncertifiedMode() {
        // Without certificates, nothing stops A from being handed the wrong public key
        // for B out of band. A signs a blob that embeds H(the key A was told is B's).
        // B's own check of that embedded digest against B's real key catches the swap.
        NonceCache cache = new NonceCache(16);
        NodeCredential credA = ca.provision(1);
        NodeCredential credB = ca.provision(2);
        NodeCredential wrongKeyForB = ca.provision(20); // an unrelated key pair

        InterlockParty a = new InterlockParty(engine, credA, false, cache);
        InterlockParty b = new InterlockParty(engine, credB, false, cache);

        // A is fed the WRONG key for "B" (substituted), while B correctly holds A's key.
        a.receivePeerCredential(2, CryptoEngine.encodePublicKey(wrongKeyForB.publicKey()), null);
        b.receivePeerCredential(1, CryptoEngine.encodePublicKey(credA.publicKey()), null);

        byte[] aFirst = a.produceFirstHalf();
        byte[] aCommit = a.commitment();
        byte[] bFirst = b.produceFirstHalf();
        byte[] bCommit = b.commitment();
        b.receiveFirstHalf(aFirst, aCommit);
        a.receiveFirstHalf(bFirst, bCommit);
        byte[] aSecond = a.produceSecondHalf();
        b.produceSecondHalf();

        // b tries to reassemble A's blob, but A encrypted it to "wrongKeyForB", not to
        // B's real public key, so B cannot even decrypt it -- key substitution is caught
        // at the latest by the point B would otherwise have checked the embedded digest.
        InterlockException ex = assertThrows(InterlockException.class, () -> b.receiveSecondHalf(aSecond));
        assertEquals(InterlockException.Reason.UNDECRYPTABLE, ex.reason());
    }
}
