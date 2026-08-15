package io.github.vijaxx.wsn.protocol;

/** Which protocol variant a simulation run uses. */
public enum SecurityMode {
    /** Textbook probabilistic-rotation LEACH: no authentication, no encryption. */
    BASELINE_LEACH,
    /** Hardened variant: RSA-1024 certified join, interlock-protected key agreement,
     *  AES-128/GCM payload encryption, and reputation-based head blacklisting. */
    SECURE_LEACH
}
