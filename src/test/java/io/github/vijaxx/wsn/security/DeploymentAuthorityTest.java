package io.github.vijaxx.wsn.security;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeploymentAuthorityTest {

    private final CryptoEngine engine = new CryptoEngine(55L);
    private final DeploymentAuthority ca = new DeploymentAuthority(engine);

    @Test
    void issuedCertificateVerifies() {
        NodeCredential cred = ca.provision(3);
        assertTrue(ca.verifyCertificate(3, cred.publicKey(), cred.certificate()));
    }

    @Test
    void certificateDoesNotVerifyForWrongNodeId() {
        NodeCredential cred = ca.provision(3);
        assertFalse(ca.verifyCertificate(4, cred.publicKey(), cred.certificate()));
    }

    @Test
    void certificateDoesNotVerifyForWrongKey() {
        NodeCredential cred = ca.provision(3);
        KeyPair other = engine.generateRsaKeyPair();
        assertFalse(ca.verifyCertificate(3, other.getPublic(), cred.certificate()));
    }

    @Test
    void certificateFromDifferentCaDoesNotVerify() {
        DeploymentAuthority otherCa = new DeploymentAuthority(engine);
        NodeCredential cred = otherCa.provision(3);
        assertFalse(ca.verifyCertificate(3, cred.publicKey(), cred.certificate()));
    }
}
