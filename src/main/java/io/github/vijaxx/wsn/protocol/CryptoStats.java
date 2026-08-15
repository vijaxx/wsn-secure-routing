package io.github.vijaxx.wsn.protocol;

/**
 * Accumulated cryptographic overhead for a secure-protocol run. Reported separately
 * from the radio energy totals because RSA/AES computation draws from the node's CPU
 * power budget, not the radio energy model this simulation implements (see README
 * limitations) -- so it is reported as wall-clock compute time and operation counts,
 * not joules.
 */
public final class CryptoStats {
    public long interlockHandshakes;
    public long rsaSignVerifyOps;
    public long rsaWrapUnwrapOps;
    public long aesEncryptOps;
    public long aesDecryptOps;
    public long authenticationFailures;
    public long handshakeNanos;
    public long extraOverheadBits;

    public double handshakeMillis() {
        return handshakeNanos / 1e6;
    }

    public double avgHandshakeMicros() {
        return interlockHandshakes == 0 ? 0.0 : (handshakeNanos / 1000.0) / interlockHandshakes;
    }
}
