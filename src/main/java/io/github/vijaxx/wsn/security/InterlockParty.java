package io.github.vijaxx.wsn.security;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * One endpoint of the Interlock Protocol (Rivest and Shamir, 1984), adapted to
 * establish a pairwise session key between a sensor node and its cluster head.
 *
 * <h2>The exchange</h2>
 * Each party builds one blob:
 * <pre>
 *   ephemeral = fresh AES-128 key
 *   payload   = senderId || nonce || secretContribution || H(peerPublicKeyAsSeen)
 *               || signature_senderPrivate(senderId || nonce || secret || H(peerKeyAsSeen))
 *   blob      = RSA-OAEP(peerPublicKeyAsSeen, ephemeral) || AES-128-GCM(ephemeral, payload)
 * </pre>
 * The blob is cut in half. The exchange then runs in four messages, strictly ordered:
 * <pre>
 *   1. A -> B : firstHalf(A), commit(A) = SHA-256(blob_A)
 *   2. B -> A : firstHalf(B), commit(B) = SHA-256(blob_B)
 *   3. A -> B : secondHalf(A)
 *   4. B -> A : secondHalf(B)
 * </pre>
 * The session key is {@code SHA-256(secret_lowId || secret_highId)} truncated to 128 bits,
 * so both endpoints derive the same AES-128 key without either choosing it alone.
 *
 * <h2>Why this defeats a man in the middle</h2>
 * The class enforces the interlock discipline mechanically: {@link #produceSecondHalf()}
 * throws unless {@link #receiveFirstHalf} has already been called. An attacker sitting
 * between A and B is therefore forced to emit her first half to B <em>before</em> she has
 * received A's second half, and half a blob is useless to her:
 * <ul>
 *   <li>the RSA-OAEP block cannot be decrypted from half its bytes, and</li>
 *   <li>AES-GCM will not release plaintext without the full ciphertext and its tag.</li>
 * </ul>
 * She cannot compute her outbound message as a function of the complete inbound message,
 * which is exactly the transparency a relay attack needs. That leaves her two options,
 * and this implementation detects both:
 * <ol>
 *   <li><b>Forward verbatim.</b> A's blob is encrypted under the key the attacker offered,
 *       so B's RSA unwrap (or the GCM tag check) fails: {@link InterlockException.Reason#UNDECRYPTABLE}.</li>
 *   <li><b>Fabricate her own blob.</b> She must sign as A without A's private key, so the
 *       inner signature fails: {@link InterlockException.Reason#BAD_SIGNATURE}. If she
 *       instead presents her own certified identity, the id inside the blob does not match
 *       the peer we intended to talk to: {@link InterlockException.Reason#IDENTITY_MISMATCH}.</li>
 * </ol>
 * The embedded {@code H(peerPublicKeyAsSeen)} adds a third net: if the attacker managed to
 * swap public keys at all, each side's view of the other's key differs from what the peer
 * signed, giving {@link InterlockException.Reason#KEY_VIEW_MISMATCH}.
 *
 * <p><b>Honest scoping.</b> With CA-certified keys, signature checking alone already stops a
 * key-substituting MITM; interlock's independent contribution is against the
 * <em>relay-and-splice</em> adversary who never has to author content, and against
 * deployments where certificates are unavailable. In that uncertified mode interlock does
 * not raise an exception, but it does force the attacker to inject content she invented
 * before seeing the genuine message; {@link MitmAdversary} exercises and asserts exactly
 * that difference. See the README.
 */
public final class InterlockParty {

    private static final byte[] AAD_CONTEXT = "WSN-INTERLOCK-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final int NONCE_BYTES = 16;
    private static final int SECRET_BYTES = 16;
    private static final int DIGEST_BYTES = 32;
    private static final int WRAPPED_KEY_BYTES = CryptoEngine.RSA_KEY_BITS / 8; // 128 for RSA-1024

    private final CryptoEngine engine;
    private final NodeCredential credential;
    private final boolean requireCertificate;
    private final NonceCache nonceCache;

    private int peerId = -1;
    private PublicKey peerKeyAsSeen;
    private byte[] myBlob;
    private byte[] myCommitment;
    private byte[] mySecret;
    private byte[] peerFirstHalf;
    private byte[] peerCommitment;
    private boolean firstHalfSent;
    private boolean secondHalfSent;
    private SecretKey sessionKey;
    private byte[] peerSecret;

    public InterlockParty(CryptoEngine engine, NodeCredential credential) {
        this(engine, credential, true, new NonceCache(4096));
    }

    /**
     * @param requireCertificate when false the party accepts a bare public key with no CA
     *                           certificate; this models a deployment without pre-distributed
     *                           credentials and is used to show what interlock does and does
     *                           not buy you on its own.
     */
    public InterlockParty(CryptoEngine engine, NodeCredential credential,
                          boolean requireCertificate, NonceCache nonceCache) {
        this.engine = engine;
        this.credential = credential;
        this.requireCertificate = requireCertificate;
        this.nonceCache = nonceCache;
    }

    public int id() {
        return credential.nodeId();
    }

    public PublicKey publicKey() {
        return credential.publicKey();
    }

    public byte[] certificate() {
        return credential.certificate();
    }

    /** The AES-128 key agreed by the exchange, or null until step 4 completes. */
    public SecretKey sessionKey() {
        return sessionKey;
    }

    /** The peer's secret contribution as this party actually received it. */
    public byte[] peerSecret() {
        return peerSecret == null ? null : peerSecret.clone();
    }

    /** This party's own secret contribution. */
    public byte[] ownSecret() {
        return mySecret == null ? null : mySecret.clone();
    }

    /**
     * Step 0: accept the peer's advertised identity. With {@code requireCertificate} the
     * certificate must verify against the deployment CA.
     */
    public void receivePeerCredential(int claimedPeerId, byte[] encodedPeerKey, byte[] certificate) {
        PublicKey key;
        try {
            key = CryptoEngine.decodePublicKey(encodedPeerKey);
        } catch (RuntimeException e) {
            throw new InterlockException(InterlockException.Reason.BAD_CERTIFICATE,
                    "peer public key is not a well-formed RSA SPKI", e);
        }
        if (requireCertificate) {
            if (certificate == null || !DeploymentAuthority.verifyCertificate(
                    engine, credential.caPublicKey(), claimedPeerId, key, certificate)) {
                throw new InterlockException(InterlockException.Reason.BAD_CERTIFICATE,
                        "no valid deployment certificate for claimed node " + claimedPeerId);
            }
        }
        this.peerId = claimedPeerId;
        this.peerKeyAsSeen = key;
    }

    /** Step 1/2: build the blob (if needed) and release its first half. */
    public byte[] produceFirstHalf() {
        if (peerKeyAsSeen == null) {
            throw new InterlockException(InterlockException.Reason.PROTOCOL_ORDER,
                    "peer credential must be accepted before the exchange starts");
        }
        if (myBlob == null) {
            buildBlob();
        }
        firstHalfSent = true;
        return Arrays.copyOfRange(myBlob, 0, midpoint(myBlob.length));
    }

    /** SHA-256 of the whole blob, published together with the first half. */
    public byte[] commitment() {
        if (myBlob == null) {
            buildBlob();
        }
        return myCommitment.clone();
    }

    /** Step 1/2 inbound: record the peer's first half and its commitment. */
    public void receiveFirstHalf(byte[] half, byte[] commitment) {
        if (peerFirstHalf != null) {
            throw new InterlockException(InterlockException.Reason.PROTOCOL_ORDER,
                    "first half already received");
        }
        this.peerFirstHalf = half.clone();
        this.peerCommitment = commitment == null ? null : commitment.clone();
    }

    /**
     * Step 3/4: release the second half.
     *
     * <p><b>This is the interlock.</b> It is refused until the peer's first half is in hand,
     * which is what denies a relay attacker the ability to transform a complete message.
     */
    public byte[] produceSecondHalf() {
        if (!firstHalfSent) {
            throw new InterlockException(InterlockException.Reason.PROTOCOL_ORDER,
                    "cannot send the second half before the first");
        }
        if (peerFirstHalf == null) {
            throw new InterlockException(InterlockException.Reason.PROTOCOL_ORDER,
                    "interlock violation: the peer's first half must arrive before our second half "
                            + "is released");
        }
        secondHalfSent = true;
        return Arrays.copyOfRange(myBlob, midpoint(myBlob.length), myBlob.length);
    }

    /** True once this party has released its second half. */
    public boolean secondHalfSent() {
        return secondHalfSent;
    }

    /**
     * Step 3/4 inbound: reassemble, verify, and derive the session key.
     *
     * @throws InterlockException on any detection rule firing
     */
    public void receiveSecondHalf(byte[] half) {
        if (peerFirstHalf == null) {
            throw new InterlockException(InterlockException.Reason.PROTOCOL_ORDER,
                    "second half arrived before the first");
        }
        byte[] blob = concat(peerFirstHalf, half);

        if (peerCommitment != null
                && !CryptoEngine.constantTimeEquals(peerCommitment, CryptoEngine.sha256(blob))) {
            throw new InterlockException(InterlockException.Reason.COMMITMENT_MISMATCH,
                    "reassembled blob does not match the digest committed with the first half");
        }
        if (blob.length <= WRAPPED_KEY_BYTES) {
            throw new InterlockException(InterlockException.Reason.UNDECRYPTABLE,
                    "blob too short to contain a wrapped key");
        }

        byte[] payload;
        try {
            SecretKey ephemeral = engine.unwrapKey(credential.keyPair().getPrivate(),
                    Arrays.copyOfRange(blob, 0, WRAPPED_KEY_BYTES));
            payload = engine.decryptGcm(ephemeral,
                    Arrays.copyOfRange(blob, WRAPPED_KEY_BYTES, blob.length), AAD_CONTEXT);
        } catch (RuntimeException e) {
            throw new InterlockException(InterlockException.Reason.UNDECRYPTABLE,
                    "the blob was not encrypted to our public key", e);
        }

        ByteBuffer bb = ByteBuffer.wrap(payload);
        int senderId = bb.getInt();
        byte[] nonce = read(bb, NONCE_BYTES);
        byte[] secret = read(bb, SECRET_BYTES);
        byte[] peerViewOfOurKey = read(bb, DIGEST_BYTES);
        int sigLen = bb.getInt();
        if (sigLen < 0 || sigLen > bb.remaining()) {
            throw new InterlockException(InterlockException.Reason.BAD_SIGNATURE,
                    "malformed signature length");
        }
        byte[] signature = read(bb, sigLen);

        if (senderId != peerId) {
            throw new InterlockException(InterlockException.Reason.IDENTITY_MISMATCH,
                    "blob claims node " + senderId + " but we are talking to " + peerId);
        }
        byte[] signedBody = signedBody(senderId, nonce, secret, peerViewOfOurKey);
        if (!engine.verify(peerKeyAsSeen, signedBody, signature)) {
            throw new InterlockException(InterlockException.Reason.BAD_SIGNATURE,
                    "inner signature does not verify under the peer's certified key");
        }
        byte[] ourKeyDigest = CryptoEngine.sha256(CryptoEngine.encodePublicKey(credential.publicKey()));
        if (!CryptoEngine.constantTimeEquals(ourKeyDigest, peerViewOfOurKey)) {
            throw new InterlockException(InterlockException.Reason.KEY_VIEW_MISMATCH,
                    "the peer signed a different view of our public key: a key was substituted");
        }
        if (nonceCache != null && !nonceCache.accept(senderId, nonce)) {
            throw new InterlockException(InterlockException.Reason.REPLAY,
                    "nonce already seen from node " + senderId);
        }

        this.peerSecret = secret;
        this.sessionKey = deriveSessionKey(credential.nodeId(), mySecret, peerId, secret);
    }

    // ------------------------------------------------------------------ internals

    private void buildBlob() {
        mySecret = new byte[SECRET_BYTES];
        engine.random().nextBytes(mySecret);
        byte[] nonce = new byte[NONCE_BYTES];
        engine.random().nextBytes(nonce);

        byte[] peerKeyDigest = CryptoEngine.sha256(CryptoEngine.encodePublicKey(peerKeyAsSeen));
        byte[] signature = engine.sign(credential.keyPair().getPrivate(),
                signedBody(credential.nodeId(), nonce, mySecret, peerKeyDigest));

        ByteBuffer bb = ByteBuffer.allocate(
                4 + NONCE_BYTES + SECRET_BYTES + DIGEST_BYTES + 4 + signature.length);
        bb.putInt(credential.nodeId()).put(nonce).put(mySecret).put(peerKeyDigest)
                .putInt(signature.length).put(signature);

        SecretKey ephemeral = engine.generateAesKey();
        byte[] wrapped = engine.wrapKey(peerKeyAsSeen, ephemeral);
        byte[] sealed = engine.encryptGcm(ephemeral, bb.array(), AAD_CONTEXT);

        myBlob = concat(wrapped, sealed);
        myCommitment = CryptoEngine.sha256(myBlob);
    }

    private static byte[] signedBody(int senderId, byte[] nonce, byte[] secret, byte[] peerKeyDigest) {
        return ByteBuffer.allocate(4 + nonce.length + secret.length + peerKeyDigest.length)
                .putInt(senderId).put(nonce).put(secret).put(peerKeyDigest).array();
    }

    /**
     * Both endpoints hash the two contributions in ascending node-id order so they agree
     * on the ordering without an extra message.
     */
    static SecretKey deriveSessionKey(int ownId, byte[] ownSecret, int peerId, byte[] peerSecret) {
        byte[] lo = ownId <= peerId ? ownSecret : peerSecret;
        byte[] hi = ownId <= peerId ? peerSecret : ownSecret;
        byte[] digest = CryptoEngine.sha256(lo, hi);
        return new SecretKeySpec(Arrays.copyOfRange(digest, 0, CryptoEngine.AES_KEY_BITS / 8), "AES");
    }

    private static int midpoint(int length) {
        return length / 2;
    }

    private static byte[] read(ByteBuffer bb, int n) {
        if (bb.remaining() < n) {
            throw new InterlockException(InterlockException.Reason.UNDECRYPTABLE,
                    "truncated payload");
        }
        byte[] out = new byte[n];
        bb.get(out);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
