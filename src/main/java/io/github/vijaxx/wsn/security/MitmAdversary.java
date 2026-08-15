package io.github.vijaxx.wsn.security;

/**
 * A man-in-the-middle harness for tests: sits between two {@link InterlockParty}
 * instances and offers a few concrete relay/splice strategies. Not used by the
 * simulator itself — this is a correctness fixture for the interlock guarantees.
 */
public final class MitmAdversary {

    private MitmAdversary() {
    }

    /** What the attacker does with the halves she intercepts. */
    public enum Strategy {
        /** Forward A's blob to B unmodified, but re-encrypt it under the attacker's own key
         *  (the classic split-and-relay MITM: she terminates both legs). */
        RELAY_UNDER_OWN_KEY,
        /** Try to answer B on A's behalf using content the attacker authored herself,
         *  before A's genuine second half has arrived. */
        FABRICATE_EARLY,
        /** Wait for both full halves, then swap and relay them verbatim between A and B
         *  (no re-encryption) — checks that honest relay-without-injection still works,
         *  i.e. that interlock does not produce false positives when there is no attack. */
        TRANSPARENT_RELAY
    }
}
