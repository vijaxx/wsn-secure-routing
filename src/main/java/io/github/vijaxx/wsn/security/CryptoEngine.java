package io.github.vijaxx.wsn.security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Thin wrapper over the JCA/JCE primitives the secure protocol actually uses.
 * Nothing here is simulated: these are real RSA-1024 and AES-128 operations run
 * by the platform provider.
 *
 * <p>Algorithms:
 * <ul>
 *   <li>RSA-1024 with SHA256withRSA signatures for node identity and join authentication</li>
 *   <li>RSA/ECB/OAEPWithSHA-256AndMGF1Padding to wrap an ephemeral AES key</li>
 *   <li>AES-128/GCM/NoPadding for authenticated payload encryption (96-bit IV, 128-bit tag)</li>
 *   <li>AES-128/CBC/PKCS5Padding as an alternative payload mode, exposed for comparison</li>
 *   <li>HmacSHA256 for per-round cluster-head announcements and TDMA schedule authentication</li>
 * </ul>
 *
 * <p>RSA-1024 is below current recommendations (NIST SP 800-57 puts the floor at 2048 bits).
 * It is used here because the research specification this simulation reproduces names
 * RSA-1024; see the limitations section of the README.
 */
public final class CryptoEngine {

    public static final int RSA_KEY_BITS = 1024;
    public static final int AES_KEY_BITS = 128;
    public static final int GCM_IV_BYTES = 12;
    public static final int GCM_TAG_BITS = 128;
    public static final int CBC_IV_BYTES = 16;

    private final SecureRandom random;

    public CryptoEngine() {
        this.random = new SecureRandom();
    }

    /**
     * Deterministic variant. The JDK's SHA1PRNG is seeded so that key material is
     * reproducible across runs, which keeps the whole simulation replayable.
     * This is a simulation aid and must never be used for production key generation.
     */
    public CryptoEngine(long seed) {
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed(seed);
            this.random = sr;
        } catch (Exception e) {
            throw new CryptoException("cannot create seeded PRNG", e);
        }
    }

    public SecureRandom random() {
        return random;
    }

    // ---------------------------------------------------------------- RSA

    public KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(RSA_KEY_BITS, random);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoException("RSA key generation failed", e);
        }
    }

    public byte[] sign(PrivateKey key, byte[] data) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(key, random);
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            throw new CryptoException("signing failed", e);
        }
    }

    public boolean verify(PublicKey key, byte[] data, byte[] signature) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            // A malformed signature is a verification failure, not a crash.
            return false;
        }
    }

    /** RSA-OAEP wrap of a 128-bit AES key. Output is exactly 128 bytes for RSA-1024. */
    public byte[] wrapKey(PublicKey peerPublic, SecretKey aesKey) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.ENCRYPT_MODE, peerPublic, random);
            return c.doFinal(aesKey.getEncoded());
        } catch (Exception e) {
            throw new CryptoException("RSA key wrap failed", e);
        }
    }

    public SecretKey unwrapKey(PrivateKey ownPrivate, byte[] wrapped) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.DECRYPT_MODE, ownPrivate);
            byte[] raw = c.doFinal(wrapped);
            return new SecretKeySpec(raw, "AES");
        } catch (Exception e) {
            throw new CryptoException("RSA key unwrap failed", e);
        }
    }

    public static byte[] encodePublicKey(PublicKey key) {
        return key.getEncoded();
    }

    public static PublicKey decodePublicKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new CryptoException("cannot decode RSA public key", e);
        }
    }

    // ---------------------------------------------------------------- AES

    public SecretKey generateAesKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(AES_KEY_BITS, random);
            return kg.generateKey();
        } catch (Exception e) {
            throw new CryptoException("AES key generation failed", e);
        }
    }

    /**
     * AES-128/GCM. The 12-byte IV is generated fresh per message and prefixed to the
     * ciphertext, so an IV is never reused under a given key.
     */
    public byte[] encryptGcm(SecretKey key, byte[] plaintext, byte[] associatedData) {
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            random.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (associatedData != null) {
                c.updateAAD(associatedData);
            }
            byte[] ct = c.doFinal(plaintext);
            return ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array();
        } catch (Exception e) {
            throw new CryptoException("AES-GCM encryption failed", e);
        }
    }

    public byte[] decryptGcm(SecretKey key, byte[] ivAndCiphertext, byte[] associatedData) {
        try {
            if (ivAndCiphertext.length < GCM_IV_BYTES + 16) {
                throw new CryptoException("ciphertext too short to contain IV and tag", null);
            }
            byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, GCM_IV_BYTES);
            byte[] ct = Arrays.copyOfRange(ivAndCiphertext, GCM_IV_BYTES, ivAndCiphertext.length);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (associatedData != null) {
                c.updateAAD(associatedData);
            }
            return c.doFinal(ct);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("AES-GCM decryption/authentication failed", e);
        }
    }

    /** AES-128/CBC with a random 16-byte IV prefixed to the ciphertext. */
    public byte[] encryptCbc(SecretKey key, byte[] plaintext) {
        try {
            byte[] iv = new byte[CBC_IV_BYTES];
            random.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] ct = c.doFinal(plaintext);
            return ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array();
        } catch (Exception e) {
            throw new CryptoException("AES-CBC encryption failed", e);
        }
    }

    public byte[] decryptCbc(SecretKey key, byte[] ivAndCiphertext) {
        try {
            byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, CBC_IV_BYTES);
            byte[] ct = Arrays.copyOfRange(ivAndCiphertext, CBC_IV_BYTES, ivAndCiphertext.length);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return c.doFinal(ct);
        } catch (Exception e) {
            throw new CryptoException("AES-CBC decryption failed", e);
        }
    }

    // ---------------------------------------------------------------- MAC / hash

    public byte[] hmac(SecretKey key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getEncoded(), "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new CryptoException("HMAC failed", e);
        }
    }

    public boolean verifyHmac(SecretKey key, byte[] data, byte[] tag) {
        return MessageDigest.isEqual(hmac(key, data), tag);
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (Exception e) {
            throw new CryptoException("SHA-256 failed", e);
        }
    }

    /** Constant-time comparison, delegated to the JDK. */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /** Unchecked wrapper so protocol code is not littered with checked-exception plumbing. */
    public static final class CryptoException extends RuntimeException {
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
