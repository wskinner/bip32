import com.google.common.annotations.VisibleForTesting;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

public class ExtendedKeyPair {
    public static int private_testnet_version = 0x04358394;
    public static int private_mainnet_version = 0x0488ADE4;
    public static int public_testnet_version = 0x043587CF;
    public static int public_mainnet_version = 0x0488B21E;

    // to be set only for private keys
    private final BigInteger privKey;

    // To be set only for public keys
    private final ECPoint pubKey;

    private final byte[] chainCode;
    private final byte depth;
    private final ExtendedKeyPair parent;
    private final byte[] childNumber;
    private final byte[] parentFingerprint;
    private final boolean isMainnet;

    /**
     * Each account is composed of two keypair chains: an internal and an external one. The external keychain is used
     * to generate new public addresses, while the internal keychain is used for all other operations (change addresses,
     * generation addresses, ..., anything that doesn't need to be communicated). Clients that do not support separate
     * keychains for these should use the external one for everything.
     * <p>
     * m/iH/0/k corresponds to the k'th keypair of the external chain of account number i of the HDW derived from master m.
     * m/iH/1/k corresponds to the k'th keypair of the internal chain of account number i of the HDW derived from master m.
     * <p>
     * The keyString may not be complete.
     *
     * @param keyString A string like /iH/0/k
     */
    public ExtendedKeyPair generate(String keyString) {
        if (depth != 0) {
            throw new UnsupportedOperationException("Only the master key pair can generate account paths");
        }

        String[] parts = keyString.split("/");
        assert parts[0].equals("m");

        if (parts.length == 1) {
            return this;
        }

        return generateSubtree(Arrays.copyOfRange(parts, 1, parts.length));
    }

    private ExtendedKeyPair generateSubtree(String[] pathParts) {
        if (pathParts.length == 0) {
            return this;
        }

        int index = parseIndex(pathParts[0]);
        ExtendedKeyPair nextSubtree = ckdPriv(index);
        return nextSubtree.generateSubtree(Arrays.copyOfRange(pathParts, 1, pathParts.length));
    }

    /**
     * The non hardened indexes include 0 through 2^31 - 1 inclusive.
     * The hardened indexes include 2^31 through 2^32 - 1 inclusive.
     * So 0h translates to 2^31, 1h translates to 2^31 + 1, and so on.
     * This code will trigger NumberFormatException if the value is out of range for an Integer.
     */
    @VisibleForTesting
    public int parseIndex(String indexString) {
        int value;
        if (indexString.toLowerCase().contains("h")) {
            value = Integer.parseInt(indexString.substring(0, indexString.length() - 1));
            value |= 0x80000000;
        } else {
            value = Integer.parseInt(indexString);
        }

        return value;
    }

    /**
     * The function CKDpriv((kpar, cpar), i) -> (ki, ci) computes a child extended private key from the parent extended private key:
     *
     * @param i
     * @return
     */
    public ExtendedKeyPair ckdPriv(int i) {
        HMac hmac = new HMac(new SHA512Digest());
        KeyParameter keyParameter = new KeyParameter(chainCode);
        hmac.init(keyParameter);

        if (i < 0) {
            // hardened
            hmac.update((byte) 0x00);
            hmac.update(Bip32.ser256(privKey), 0, 32);
        } else {
            // non-hardened
            byte[] data = Bip32.serP(Bip32.point(privKey));
            hmac.update(data, 0, data.length);
        }

        byte[] indexData = Bip32.ser32(i);
        hmac.update(indexData, 0, indexData.length);

        byte[] digest = new byte[64];
        hmac.doFinal(digest, 0);

        byte[] iL = new byte[32];
        byte[] iR = new byte[32];
        System.arraycopy(digest, 0, iL, 0, 32);
        System.arraycopy(digest, 32, iR, 0, 32);

        BigInteger parsediL = Bip32.parse256(iL);

        BigInteger childPrivKey = parsediL.add(this.privKey).mod(Bip32.curve.getN());
        if (parsediL.compareTo(Bip32.curve.getN()) >= 0 || childPrivKey.compareTo(BigInteger.ZERO) == 0) {
            // key is invalid. happens with probability 2^(-127)
            return null;
        }

        return new Builder()
                .setPrivKey(childPrivKey)
                .setChainCode(iR)
                .setParent(this)
                .setDepth((byte) (depth + 1))
                .setIsMainnet(isMainnet)
                .setChildNumber(Bip32.ser32(i))
                .build();

    }

    /**
     * The function CKDpub((Kpar, cpar), i) -> (Ki, ci) computes a child extended public key from the parent extended
     * public key. It is only defined for non-hardened child keys.
     */
    public ExtendedKeyPair ckdPub(int i) {
        if (i < 0) {
            // hardened
            throw new UnsupportedOperationException("ckdPub is undefined for hardened keys.");
        }

        HMac hmac = new HMac(new SHA512Digest());
        KeyParameter keyParameter = new KeyParameter(chainCode);
        hmac.init(keyParameter);

        byte[] serP = Bip32.serP(pubKey);
        hmac.update(serP, 0, serP.length);

        byte[] serI = Bip32.ser32(i);
        hmac.update(serI, 0, serI.length);

        byte[] digest = new byte[64];
        hmac.doFinal(digest, 0);

        byte[] iL = new byte[32];
        byte[] iR = new byte[32];
        System.arraycopy(digest, 0, iL, 0, 32);
        System.arraycopy(digest, 32, iR, 0, 32);

        BigInteger parsediL = Bip32.parse256(iL);

        ECPoint childPubKey = Bip32.point(parsediL).add(this.pubKey);
        if (parsediL.compareTo(Bip32.curve.getN()) >= 0 || childPubKey.isInfinity()) {
            // key is invalid. happens with probability 2^(-127)
            return null;
        }

        return new Builder()
                .setPubKey(childPubKey)
                .setChainCode(iR)
                .setParent(this)
                .setDepth((byte) (depth + 1))
                .setIsMainnet(isMainnet)
                .setChildNumber(Bip32.ser32(i))
                .build();
    }

    /**
     * The function N((k, c)) -> (K, c) computes the extended public key corresponding to an extended private key
     * (the "neutered" version, as it removes the ability to sign transactions).
     *
     * @return
     */
    public ExtendedKeyPair neuter() {
        return new Builder()
                .setPubKey(Bip32.point(privKey))
                .setChildNumber(childNumber)
                .setDepth(depth)
                .setIsMainnet(isMainnet)
                .setChainCode(chainCode)
                .setParent(parent)
                .setParentFingerprint(parentFingerprint)
                .build();
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
                .setParentFingerprint(fingerprint);
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

        // parent parentFingerprint
        byte[] fingerprint = parentFingerprint;
        ser[5] = fingerprint[0];
        ser[6] = fingerprint[1];
        ser[7] = fingerprint[2];
        ser[8] = fingerprint[3];

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

        // parent parentFingerprint
        if (parent != null) {
            byte[] fingerprint = parentFingerprint;
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
                            final byte[] parentFingerprint,
                            final ECPoint pubKey) {
        this.privKey = privKey;
        this.isMainnet = isMainnet;
        this.chainCode = chainCode;
        this.depth = depth;
        this.parent = parent;
        this.childNumber = childNumber;
        this.parentFingerprint = parentFingerprint;
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

        public Builder setParentFingerprint(byte[] fingerprint) {
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

            if (parent != null) {
                byte[] pubKeyHash = Bip32.hash160(parent.pubKey);
                fingerprint = Arrays.copyOfRange(pubKeyHash, 0, 4);
            } else {
                fingerprint = new byte[]{0, 0, 0, 0};
            }

            return new ExtendedKeyPair(this);
        }
    }

    public BigInteger getPrivKey() {
        return privKey;
    }

    public ECPoint getPubKey() {
        return pubKey;
    }

    public byte[] getChainCode() {
        return chainCode;
    }

    public byte getDepth() {
        return depth;
    }

    public ExtendedKeyPair getParent() {
        return parent;
    }

    public byte[] getChildNumber() {
        return childNumber;
    }

    public byte[] getParentFingerprint() {
        return parentFingerprint;
    }

    public boolean isMainnet() {
        return isMainnet;
    }
}
