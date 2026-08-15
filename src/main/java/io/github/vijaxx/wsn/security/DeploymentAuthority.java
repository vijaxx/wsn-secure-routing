package io.github.vijaxx.wsn.security;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * The base station acting as a deployment-time certification authority.
 *
 * <p>Before deployment every node is issued an RSA-1024 identity key pair and a
 * certificate: the CA's signature over {@code (nodeId || SPKI(nodePublicKey))}.
 * Nodes carry the CA public key, so any node can check any other node's identity in
 * the field without contacting the base station. This is the standard pre-deployment
 * keying assumption for WSN security work.
 */
public final class DeploymentAuthority {

    private final CryptoEngine engine;
    private final KeyPair caKeyPair;

    public DeploymentAuthority(CryptoEngine engine) {
        this.engine = engine;
        this.caKeyPair = engine.generateRsaKeyPair();
    }

    public PublicKey caPublicKey() {
        return caKeyPair.getPublic();
    }

    /** Bytes that a certificate signs over. */
    public static byte[] certificateBody(int nodeId, PublicKey nodeKey) {
        byte[] spki = CryptoEngine.encodePublicKey(nodeKey);
        return ByteBuffer.allocate(4 + spki.length).putInt(nodeId).put(spki).array();
    }

    /** Issues a certificate binding {@code nodeId} to {@code nodeKey}. */
    public byte[] issueCertificate(int nodeId, PublicKey nodeKey) {
        return engine.sign(caKeyPair.getPrivate(), certificateBody(nodeId, nodeKey));
    }

    /** Verifies a certificate against this CA. */
    public boolean verifyCertificate(int nodeId, PublicKey nodeKey, byte[] certificate) {
        return engine.verify(caPublicKey(), certificateBody(nodeId, nodeKey), certificate);
    }

    /** Static verification against an arbitrary CA key, for parties that only hold the key. */
    public static boolean verifyCertificate(CryptoEngine engine, PublicKey caKey,
                                            int nodeId, PublicKey nodeKey, byte[] certificate) {
        return engine.verify(caKey, certificateBody(nodeId, nodeKey), certificate);
    }

    /** Provisions a node: fresh key pair plus its certificate. */
    public NodeCredential provision(int nodeId) {
        KeyPair kp = engine.generateRsaKeyPair();
        return new NodeCredential(nodeId, kp, issueCertificate(nodeId, kp.getPublic()), caPublicKey());
    }
}
