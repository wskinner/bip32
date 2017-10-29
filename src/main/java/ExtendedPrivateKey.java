import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.util.Arrays;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.math.BigInteger;

public class ExtendedPrivateKey {
    public static int mainnet_version = 0x0488ADE4;
    public static int testnet_version = 0x04358394;

    final BigInteger k;
    final byte[] c;
    private final int depth;
    private final ExtendedPrivateKey parent;
    private final byte[] childNumber;
    private final int version;

    public ExtendedPrivateKey(BigInteger k,
                              byte[] c,
                              int depth,
                              ExtendedPrivateKey parent,
                              byte[] childNumber,
                              int version) {
        this.k = k;
        this.c = c;
        this.depth = depth;
        this.parent = parent;
        this.childNumber = childNumber;
        this.version = version;
    }

    public static ExtendedPrivateKey parse(String base58Encoded) {
        byte[] bytes = Base58.decode(base58Encoded);

        // version
        int version = 0;
        version |= ((bytes[0] & 0xff) << 24);
        version |= ((bytes[1] & 0xff) << 16);
        version |= ((bytes[2] & 0xff) << 8);
        version |= (bytes[3] & 0xff);

        // depth
        int depth = bytes[4];

        byte[] fingerprint = Arrays.copyOfRange(bytes, 5, 9);
        byte[] childNumber = Arrays.copyOfRange(bytes, 9, 13);
        byte[] chainCode = Arrays.copyOfRange(bytes, 13, 45);
        byte[] privateKey = Arrays.copyOfRange(bytes, 45, 78);
        BigInteger k = Bip32.parse256(Arrays.copyOfRange(privateKey, 1, 33));

        return new ExtendedPrivateKey(k, chainCode, depth, null, childNumber, version);
    }

    public String toString() {
        // version
        int mask = 0xFF;
        byte[] ser = new byte[82];
        ser[3] = (byte) (mask & version);
        ser[2] = (byte) (((mask << 8) & version) >>> 8);
        ser[1] = (byte) (((mask << 16) & version) >>> 16);
        ser[0] = (byte) (((mask << 24) & version) >>> 24);

        // depth
        ser[4] = (byte) depth;

        // parent fingerprint
        if (parent != null) {
            byte[] fingerprint = parent.getFingerprint();
            ser[5] = fingerprint[0];
            ser[6] = fingerprint[1];
            ser[7] = fingerprint[2];
            ser[8] = fingerprint[3];
        }

        // child number
        if (childNumber != null) {
            ser[9] = childNumber[0];
            ser[10] = childNumber[1];
            ser[11] = childNumber[2];
            ser[12] = childNumber[3];
        }

        // chain code
        System.arraycopy(c, 0, ser, 13, 32);
        System.arraycopy(Bip32.ser256(k), 0, ser, 46, 32);

        byte[] checksum = Arrays.copyOfRange(
                Sha256Hash.hashTwice(Arrays.copyOfRange(ser, 0, 78)), 0, 4);
        System.arraycopy(checksum, 0, ser, 78, 4);
        return Base58.encode(ser);
    }

    private byte[] getFingerprint() {
        throw new NotImplementedException();
    }
}
