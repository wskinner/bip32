import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Security;

public class Bip32 {
    private final ECCurve curve;
    private final ECPoint basePoint;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public Bip32() {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        curve = ecSpec.getCurve();
        basePoint = curve.createPoint(
                new BigInteger("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
                new BigInteger("32670510020758816978083085130507043184471273380659243275938904335757337482424"));
    }

    /**
     * point(p): returns the coordinate pair resulting from EC point multiplication (repeated application of the EC
     * group operation) of the secp256k1 base point with the integer p.
     * <p>
     * The secp256k1 base point is (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     * 32670510020758816978083085130507043184471273380659243275938904335757337482424)
     */
    ECPoint point(BigInteger p) {
        return basePoint.multiply(p);
    }

    /**
     * ser32(i): serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
     */
    byte[] ser32(int i) {
        return ByteBuffer.allocate(4).putInt(i).array();
    }

    byte[] ser256(BigInteger p) {
        if (p.compareTo(BigInteger.ZERO) < 0) {
            BigInteger TWO_COMPL_REF = BigInteger.ONE.shiftLeft(256);
            p = p.add(TWO_COMPL_REF);
        }

        byte[] twos = p.toByteArray();
        // BigInteger's toByteArray() gives us a big endian twos complement representation, so the leftmost byte is the
        // sign.
        if (twos.length != 33) {
            byte[] newTwos = new byte[33];
            for (int i = 0; i < twos.length; i++) {
                newTwos[32 - twos.length + i] = twos[i];
            }
            twos = newTwos;
        }

        byte[] unsigned = new byte[32];
        for (int i = 1; i < 33; i++) {
            unsigned[i - 1] = twos[i];
        }

        return unsigned;
    }

    /**
     * serP(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form:
     * (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted y coordinate.
     * <p>
     * The algorithm is specified at: http://www.secg.org/SEC1-Ver-1.0.pdf
     */
    byte[] serP(ECPoint P) {
        int bitlen = P.getRawXCoord().bitLength();
        int bytelen = Math.max(bitlen / 8, (bitlen + (bitlen - (bitlen % 8))) / 8);
        byte[] result = new byte[bytelen + 1];

        boolean yp = P.getRawYCoord().testBitZero();
        if (yp) {
            result[0] = 0x03;
        } else {
            result[0] = 0x02;
        }

        byte[] serX = ser256(P.getRawXCoord().toBigInteger());
        System.arraycopy(serX, 0, result, 1, serX.length);

        return result;
    }

    /**
     * parse256(p): interprets a 32-byte sequence as a 256-bit number, most significant byte first
     */
    BigInteger parse256(byte[] p) {
        return new BigInteger(1, p);
    }

}
