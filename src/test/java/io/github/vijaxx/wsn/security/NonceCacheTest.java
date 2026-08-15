package io.github.vijaxx.wsn.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NonceCacheTest {

    @Test
    void firstUseOfANonceIsAccepted() {
        NonceCache cache = new NonceCache(16);
        assertTrue(cache.accept(1, new byte[] {1, 2, 3}));
    }

    @Test
    void repeatedNonceFromSameSenderIsRejected() {
        NonceCache cache = new NonceCache(16);
        byte[] nonce = {9, 9, 9};
        assertTrue(cache.accept(5, nonce));
        assertFalse(cache.accept(5, nonce));
    }

    @Test
    void sameNonceBytesFromDifferentSendersAreIndependent() {
        NonceCache cache = new NonceCache(16);
        byte[] nonce = {1, 1, 1};
        assertTrue(cache.accept(1, nonce));
        assertTrue(cache.accept(2, nonce));
    }

    @Test
    void capacityEvictsOldestEntryPerSender() {
        NonceCache cache = new NonceCache(2);
        cache.accept(1, new byte[] {0});
        cache.accept(1, new byte[] {1});
        cache.accept(1, new byte[] {2}); // evicts nonce {0}
        assertTrue(cache.accept(1, new byte[] {0}), "evicted nonce should be acceptable again");
    }
}
