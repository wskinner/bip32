import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

public class ExtendedKeyPair {
    public static int private_testnet_version = 0x04358394;
    public static int private_mainnet_version = 0x0488ADE4;
    public static int public_testnet_version = 0x043587CF;
    public static int public_mainnet_version = 0x0488B21E;

    // to be set only for private keys
    final BigInteger privKey;

    // To be set only for public keys
    final ECPoint pubKey;

    final byte[] chainCode;
    final byte depth;
    final ExtendedKeyPair parent;
    final byte[] childNumber;
    final byte[] fingerprint;
    final boolean isMainnet;

    /**
     * Each account is composed of two keypair chains: an internal and an external one. The external keychain is used
     * to generate new public addresses, while the internal keychain is used for all other operations (change addresses,
     * generation addresses, ..., anything that doesn't need to be communicated). Clients that do not support separate
     * keychains for these should use the external one for everything.
     *
     * m/iH/0/k corresponds to the k'th keypair of the external chain of account number i of the HDW derived from master m.
     * m/iH/1/k corresponds to the k'th keypair of the internal chain of account number i of the HDW derived from master m.
     *
     * @param keyString A string like /iH/0/k
     */
    public ExtendedKeyPair generate(String keyString) {
        return null;
    }

    public static ExtendedKeyPair parseBase58Check(String base58Encoded) {
        byte[] bytes = Base58.decode(base58Encoded);

        // version
        int version = 0;
        version |= ((bytes[0] & 0xff) << 24);
        version |= ((bytes[1] & 0xff) << 16);
        version |= ((bytes[2] & 0xff) << 8);
        version |= (bytes[3] & 0xff);

        // depth
        byte depth = bytes[4];

        byte[] fingerprint = Arrays.copyOfRange(bytes, 5, 9);
        byte[] childNumber = Arrays.copyOfRange(bytes, 9, 13);
        byte[] chainCode = Arrays.copyOfRange(bytes, 13, 45);

        ECPoint pubKey = null;
        BigInteger privKey = null;
        if (bytes[45] != 0) {
            pubKey = Bip32.curve.getCurve().decodePoint(Arrays.copyOfRange(bytes, 45, 78));
        } else {
            privKey = Bip32.parse256(Arrays.copyOfRange(bytes, 46, 78));
        }

        Builder builder = new Builder()
                .setChainCode(chainCode)
                .setDepth(depth)
                .setChildNumber(childNumber)
                .setIsMainnet(version == public_mainnet_version || version == private_mainnet_version)
                .setFingerprint(fingerprint);
        if (pubKey != null) {
            return builder.setPubKey(pubKey).build();
        } else {
            return builder.setPrivKey(privKey).build();
        }
    }

    public String serializePub() {
        // version
        int version = isMainnet ? public_mainnet_version : public_testnet_version;
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

        byte[] keybytes = pubKey.getEncoded(true);
        System.arraycopy(keybytes, 0, ser, 45, 33);

        byte[] checksum = Arrays.copyOfRange(
                Sha256Hash.hashTwice(Arrays.copyOfRange(ser, 0, 78)), 0, 4);
        System.arraycopy(checksum, 0, ser, 78, 4);
        return Base58.encode(ser);
    }

    public String serializePriv() {
        // version
        int version = isMainnet ? private_mainnet_version : private_testnet_version;
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

        // key
        System.arraycopy(Bip32.ser256(privKey), 0, ser, 46, 32);

        byte[] checksum = Arrays.copyOfRange(
                Sha256Hash.hashTwice(Arrays.copyOfRange(ser, 0, 78)), 0, 4);
        System.arraycopy(checksum, 0, ser, 78, 4);
        return Base58.encode(ser);
    }

    ExtendedKeyPair(Builder builder) {
        this(builder.privKey,
                builder.isMainnet,
                builder.chainCode,
                builder.depth,
                builder.parent,
                builder.childNumber,
                builder.fingerprint,
                builder.pubKey);
    }

    private ExtendedKeyPair(final BigInteger privKey,
                            final boolean isMainnet,
                            final byte[] chainCode,
                            final byte depth,
                            final ExtendedKeyPair parent,
                            final byte[] childNumber,
                            final byte[] fingerprint,
                            final ECPoint pubKey) {
        this.privKey = privKey;
        this.isMainnet = isMainnet;
        this.chainCode = chainCode;
        this.depth = depth;
        this.parent = parent;
        this.childNumber = childNumber;
        this.fingerprint = fingerprint;
        this.pubKey = pubKey;
    }

    public static class Builder {
        BigInteger privKey;
        byte[] chainCode;
        boolean isMainnet;
        byte depth;
        ExtendedKeyPair parent;
        byte[] childNumber;
        byte[] fingerprint;
        ECPoint pubKey;

        public Builder setPrivKey(BigInteger privKey) {
            this.privKey = privKey;
            return this;
        }

        public Builder setChainCode(byte[] chainCode) {
            this.chainCode = chainCode;
            return this;
        }

        public Builder setIsMainnet(boolean isMainnet) {
            this.isMainnet = isMainnet;
            return this;
        }

        public Builder setDepth(byte depth) {
            this.depth = depth;
            return this;
        }

        public Builder setParent(ExtendedKeyPair parent) {
            this.parent = parent;
            return this;
        }

        public Builder setChildNumber(byte[] childNumber) {
            this.childNumber = childNumber;
            return this;
        }

        public Builder setFingerprint(byte[] fingerprint) {
            this.fingerprint = fingerprint;
            return this;
        }

        public Builder setPubKey(ECPoint pubKey) {
            this.pubKey = pubKey;
            return this;
        }

        public ExtendedKeyPair build() {
            assert chainCode != null;
            if (privKey != null) {
                pubKey = Bip32.point(privKey);
            } else {
                assert pubKey != null;
            }

            return new ExtendedKeyPair(this);
        }
    }
}
