package io.github.vijaxx.wsn.security;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bounded per-sender replay cache. Accepts a (senderId, nonce) pair only once; a
 * capacity-bounded LRU per sender keeps memory flat over a long-running simulation.
 * This is what lets the secure protocol reject a replayed interlock message or a
 * replayed sensor report as a defence against relay/replay-flavoured DoS.
 */
public final class NonceCache {

    private final int capacityPerSender;
    private final Map<Integer, Map<String, Boolean>> seenBySender = new LinkedHashMap<>();

    public NonceCache(int capacityPerSender) {
        if (capacityPerSender <= 0) {
            throw new IllegalArgumentException("capacityPerSender must be > 0");
        }
        this.capacityPerSender = capacityPerSender;
    }

    /** Returns true and records the nonce if it has not been seen from this sender before. */
    public synchronized boolean accept(int senderId, byte[] nonce) {
        String key = toHex(nonce);
        Map<String, Boolean> seen = seenBySender.computeIfAbsent(senderId, id -> new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                return size() > capacityPerSender;
            }
        });
        if (seen.containsKey(key)) {
            return false;
        }
        seen.put(key, Boolean.TRUE);
        return true;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
