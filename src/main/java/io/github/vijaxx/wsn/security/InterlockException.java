package io.github.vijaxx.wsn.security;

/**
 * Raised whenever a party in the interlock exchange sees something that cannot have
 * come from an honest peer. Every throw site corresponds to a concrete detection rule,
 * recorded in {@link #reason()}.
 */
public class InterlockException extends RuntimeException {

    /** The specific check that fired. */
    public enum Reason {
        /** The offered identity certificate did not verify against the deployment CA. */
        BAD_CERTIFICATE,
        /** The assembled blob did not match the digest committed with the first half. */
        COMMITMENT_MISMATCH,
        /** RSA unwrap or AES-GCM authentication failed: the blob was not encrypted to us. */
        UNDECRYPTABLE,
        /** The inner signature did not verify under the peer's certified public key. */
        BAD_SIGNATURE,
        /** The peer's view of our public key differs from our own: a key was substituted. */
        KEY_VIEW_MISMATCH,
        /** The claimed sender id inside the blob is not the peer we are talking to. */
        IDENTITY_MISMATCH,
        /** A nonce was replayed. */
        REPLAY,
        /** The interlock ordering discipline was violated. */
        PROTOCOL_ORDER
    }

    private final Reason reason;

    public InterlockException(Reason reason, String message) {
        super(reason + ": " + message);
        this.reason = reason;
    }

    public InterlockException(Reason reason, String message, Throwable cause) {
        super(reason + ": " + message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
