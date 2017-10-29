import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class ExtendedPrivateKey extends ExtendedKey {
    public static int testnet_version = 0x04358394;
    public static int mainnet_version = 0x0488ADE4;


    public ExtendedPrivateKey(ExtendedKey.Builder builder) {
        super(builder);
    }

    public ExtendedPublicKey generatePublicKey() {
        ECPoint publicPoint = Bip32.point(key);
        byte[] serialized = Bip32.serP(publicPoint);
        boolean yParity = serialized[0] == 0x03;

        return new Builder()
                .setKey(publicPoint.getRawXCoord().toBigInteger())
                .setYParity(yParity)
                .setChainCode(chainCode)
                .setDepth(depth)
                .setChildNumber(childNumber)
                .setVersion(version == mainnet_version ? ExtendedPublicKey.mainnet_version : ExtendedPublicKey.testnet_version)
                .setFingerprint(fingerprint)
                .buildPublicKey();
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
            byte[] fingerprint = parent.fingerprint;
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
        System.arraycopy(chainCode, 0, ser, 13, 32);
        System.arraycopy(Bip32.ser256(key), 0, ser, 46, 32);

        byte[] checksum = Arrays.copyOfRange(
                Sha256Hash.hashTwice(Arrays.copyOfRange(ser, 0, 78)), 0, 4);
        System.arraycopy(checksum, 0, ser, 78, 4);
        return Base58.encode(ser);
    }

    private byte[] getFingerprint() {
        throw new NotImplementedException();
    }

}
