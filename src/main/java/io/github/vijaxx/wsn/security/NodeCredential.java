package io.github.vijaxx.wsn.security;

import java.security.KeyPair;
import java.security.PublicKey;

/** A node's long-term identity material: RSA-1024 key pair, CA certificate, CA public key. */
public final class NodeCredential {

    private final int nodeId;
    private final KeyPair keyPair;
    private final byte[] certificate;
    private final PublicKey caPublicKey;

    public NodeCredential(int nodeId, KeyPair keyPair, byte[] certificate, PublicKey caPublicKey) {
        this.nodeId = nodeId;
        this.keyPair = keyPair;
        this.certificate = certificate.clone();
        this.caPublicKey = caPublicKey;
    }

    public int nodeId() {
        return nodeId;
    }

    public KeyPair keyPair() {
        return keyPair;
    }

    public PublicKey publicKey() {
        return keyPair.getPublic();
    }

    public byte[] certificate() {
        return certificate.clone();
    }

    public PublicKey caPublicKey() {
        return caPublicKey;
    }
}
