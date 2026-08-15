package io.github.vijaxx.wsn.security;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoEngineTest {

    private final CryptoEngine engine = new CryptoEngine(1234L);

    @Test
    void rsaSignVerifyRoundTripsAndDetectsTampering() {
        KeyPair kp = engine.generateRsaKeyPair();
        assertEquals(CryptoEngine.RSA_KEY_BITS, ((java.security.interfaces.RSAKey) kp.getPublic()).getModulus().bitLength());
        byte[] data = "cluster-head-announcement round 17".getBytes();
        byte[] sig = engine.sign(kp.getPrivate(), data);
        assertTrue(engine.verify(kp.getPublic(), data, sig));

        byte[] tampered = "cluster-head-announcement round 18".getBytes();
        assertFalse(engine.verify(kp.getPublic(), tampered, sig));

        KeyPair other = engine.generateRsaKeyPair();
        assertFalse(engine.verify(other.getPublic(), data, sig));
    }

    @Test
    void rsaKeyWrapUnwrapRecoversTheSameAesKey() {
        KeyPair kp = engine.generateRsaKeyPair();
        SecretKey aes = engine.generateAesKey();
        byte[] wrapped = engine.wrapKey(kp.getPublic(), aes);
        assertEquals(CryptoEngine.RSA_KEY_BITS / 8, wrapped.length);
        SecretKey recovered = engine.unwrapKey(kp.getPrivate(), wrapped);
        assertArrayEquals(aes.getEncoded(), recovered.getEncoded());
    }

    @Test
    void aesGcmRoundTripsAndDetectsTamperedCiphertext() {
        SecretKey key = engine.generateAesKey();
        byte[] plaintext = "27.3C,61%RH".getBytes();
        byte[] aad = "node-7".getBytes();
        byte[] ct = engine.encryptGcm(key, plaintext, aad);
        byte[] recovered = engine.decryptGcm(key, ct, aad);
        assertArrayEquals(plaintext, recovered);

        byte[] tampered = ct.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertThrows(CryptoEngine.CryptoException.class, () -> engine.decryptGcm(key, tampered, aad));
    }

    @Test
    void aesGcmUsesFreshIvEveryCall() {
        SecretKey key = engine.generateAesKey();
        byte[] plaintext = "same message".getBytes();
        byte[] c1 = engine.encryptGcm(key, plaintext, null);
        byte[] c2 = engine.encryptGcm(key, plaintext, null);
        assertFalse(Arrays.equals(c1, c2), "ciphertexts must differ due to random IVs");
        byte[] iv1 = Arrays.copyOfRange(c1, 0, CryptoEngine.GCM_IV_BYTES);
        byte[] iv2 = Arrays.copyOfRange(c2, 0, CryptoEngine.GCM_IV_BYTES);
        assertFalse(Arrays.equals(iv1, iv2));
    }

    @Test
    void aesCbcRoundTrips() {
        SecretKey key = engine.generateAesKey();
        byte[] plaintext = "block-mode payload of arbitrary length".getBytes();
        byte[] ct = engine.encryptCbc(key, plaintext);
        assertArrayEquals(plaintext, engine.decryptCbc(key, ct));
    }

    @Test
    void hmacVerifiesOnlyForMatchingKeyAndData() {
        SecretKey key = engine.generateAesKey();
        byte[] data = "tdma-schedule-round-4".getBytes();
        byte[] tag = engine.hmac(key, data);
        assertTrue(engine.verifyHmac(key, data, tag));
        assertFalse(engine.verifyHmac(key, "tdma-schedule-round-5".getBytes(), tag));
    }

    @Test
    void seededEngineIsReproducible() {
        CryptoEngine a = new CryptoEngine(777L);
        CryptoEngine b = new CryptoEngine(777L);
        KeyPair kpA = a.generateRsaKeyPair();
        KeyPair kpB = b.generateRsaKeyPair();
        assertArrayEquals(kpA.getPublic().getEncoded(), kpB.getPublic().getEncoded());
    }

    @Test
    void differentSeedsProduceDifferentKeys() {
        CryptoEngine a = new CryptoEngine(1L);
        CryptoEngine b = new CryptoEngine(2L);
        assertNotEquals(
                Arrays.toString(a.generateRsaKeyPair().getPublic().getEncoded()),
                Arrays.toString(b.generateRsaKeyPair().getPublic().getEncoded()));
    }
}
