import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Bip32 {
    static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static ExtendedKeyPair generateMasterKey(byte[] seed) {
        return generateMasterKey(seed, true);
    }

    static ExtendedKeyPair generateMasterKey(byte[] seed, boolean isMainnet) {
        HMac hmac = new HMac(new SHA512Digest());
        KeyParameter key = new KeyParameter("Bitcoin seed".getBytes());
        hmac.init(key);
        for (byte b : seed) {
            hmac.update(b);
        }
        byte[] digest = new byte[64];
        hmac.doFinal(digest, 0);
        byte[] l = new byte[32];
        byte[] r = new byte[32];
        System.arraycopy(digest, 0, l, 0, 32);
        System.arraycopy(digest, 32, r, 0, 32);

        BigInteger k = parse256(l);
        return new ExtendedKeyPair.Builder()
                .setPrivKey(k)
                .setChainCode(r)
                .setIsMainnet(isMainnet)
                .build();
    }

    public static byte[] hash160(ECPoint pubKey) {
        SHA256Digest sha256 = new SHA256Digest();
        RIPEMD160Digest ripemd160 = new RIPEMD160Digest();

        byte[] pubBytes = pubKey.getEncoded(true);
        sha256.update(pubBytes, 0, pubBytes.length);
        byte[] sha256Out = new byte[32];
        sha256.doFinal(sha256Out, 0);
        ripemd160.update(sha256Out, 0, 32);

        byte[] ripemdOut = new byte[20];
        ripemd160.doFinal(ripemdOut, 0);

        return ripemdOut;
    }

//    public ExtendedKeyPair privateParentToPrivateChild(ExtendedPrivateKey parent, int i) {
//        HMac hmac = new HMac(new SHA512Digest());
//        KeyParameter keyParameter = new KeyParameter(parent.chainCode);
//        hmac.init(keyParameter);
//
//        if (i < 0) {
//            // hardened
//            hmac.update((byte) 0x00);
//            for (byte b : ser256(parent.privKey)) {
//                hmac.update(b);
//            }
//        } else {
//            // non-hardened
//            for (byte b : serP(point(parent.privKey))) {
//                hmac.update(b);
//            }
//        }
//
//        for (byte b : ser32(i)) {
//            hmac.update(b);
//        }
//
//        byte[] digest = new byte[64];
//        hmac.doFinal(digest, 0);
//
//        byte[] iL = new byte[32];
//        byte[] iR = new byte[32];
//        System.arraycopy(digest, 0, iL, 0, 32);
//        System.arraycopy(digest, 32, iR, 0, 32);
//
//        BigInteger Ki = parse256(iL).add(parent.privKey);
//        byte[] chaini = iR;
//
//        // In case parse256(IL) ≥ n or ki = 0, the resulting privKey is invalid, and one should proceed with the next value
//        // for i. (Note: this has probability lower than 1 in 2127.) TODO
////        return new ExtendedPrivateKey(Ki, chaini, );
//        return null;
//    }
//
//    public ExtendedPublicKey publicParentToPublicChild(ExtendedPublicKey parent, int i) {
//        throw new NotImplementedException();
//    }
//
//    public ExtendedPublicKey privateParentToPublicChild(ExtendedPrivateKey parent, int i) {
//        throw new NotImplementedException();
//    }

    /**
     * point(p): returns the coordinate pair resulting from EC point multiplication (repeated application of the EC
     * group operation) of the secp256k1 base point with the integer p.
     * <p>
     * The secp256k1 base point is (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     * 32670510020758816978083085130507043184471273380659243275938904335757337482424)
     */
    static ECPoint point(BigInteger p) {
        return curve.getG().multiply(p);
    }

    /**
     * ser32(i): serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
     */
    static byte[] ser32(int i) {
        return ByteBuffer.allocate(4).putInt(i).array();
    }

    /**
     * TODO there must be a better way
     *
     * @param p
     * @return
     */
    static byte[] ser256(BigInteger p) {
        if (p.compareTo(BigInteger.ZERO) < 0) {
            BigInteger TWO_COMPL_REF = BigInteger.ONE.shiftLeft(256);
            p = p.add(TWO_COMPL_REF);
        }

        byte[] twos = p.toByteArray();
        // BigInteger's toByteArray() gives us a big endian twos complement representation, so the leftmost byte is the
        // sign.
        int paddingNeeded = 33 - twos.length;
        if (paddingNeeded > 0) {
            byte[] newTwos = new byte[33];
            System.arraycopy(twos, 0, newTwos, paddingNeeded, 33 - paddingNeeded);
            twos = newTwos;
        }

        byte[] unsigned = new byte[32];
        System.arraycopy(twos, 1, unsigned, 0, 32);

//        System.out.println("ser256: " + Hex.toHexString(unsigned));

        return unsigned;
    }

    /**
     * serP(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form:
     * (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted y coordinate.
     * <p>
     * The algorithm is specified at: http://www.secg.org/SEC1-Ver-1.0.pdf
     */
    static byte[] serP(ECPoint P) {
        return P.getEncoded(true);
    }

    /**
     * parse256(p): interprets a 32-byte sequence as a 256-bit number, most significant byte first
     */
    static BigInteger parse256(byte[] p) {
        return new BigInteger(1, p);
    }

}
