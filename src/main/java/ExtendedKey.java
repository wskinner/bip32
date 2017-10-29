import org.bitcoinj.core.Base58;

import java.math.BigInteger;
import java.util.Arrays;

public abstract class ExtendedKey {
    // to be set only for private keys
    final BigInteger key;

    // To be set only for public keys
    final Boolean yParity;

    final byte[] chainCode;
    final int version;
    final byte depth;
    final ExtendedKey parent;
    final byte[] childNumber;
    final byte[] fingerprint;

    public static ExtendedKey parse(String base58Encoded) {
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
        byte[] key = Arrays.copyOfRange(bytes, 45, 78);
        BigInteger k = Bip32.parse256(Arrays.copyOfRange(key, 1, 33));

        Boolean yParity = null;
        if (key[0] != 0) {
            // Public key
            yParity = key[0] == 0x03;
        }

        Builder builder = new Builder()
                .setKey(k)
                .setYParity(yParity)
                .setChainCode(chainCode)
                .setDepth(depth)
                .setChildNumber(childNumber)
                .setVersion(version)
                .setFingerprint(fingerprint);
        if (yParity != null) {
            return builder.buildPublicKey();
        } else {
            return builder.buildPrivateKey();
        }
    }

    public static ExtendedPublicKey parsePublicKey(String base58Encoded) {
        ExtendedKey key = parse(base58Encoded);
        assert key instanceof ExtendedPublicKey;
        return (ExtendedPublicKey) key;
    }

    public static ExtendedPrivateKey parsePrivateKey(String base58Encoded) {
        ExtendedKey key = parse(base58Encoded);
        assert key instanceof ExtendedPrivateKey;
        return (ExtendedPrivateKey) key;
    }

    ExtendedKey(Builder builder) {
        this(builder.key,
                builder.version,
                builder.chainCode,
                builder.depth,
                builder.parent,
                builder.childNumber,
                builder.fingerprint,
                builder.yParity);
    }

    private ExtendedKey(final BigInteger X,
                        final int version,
                        final byte[] chainCode,
                        final byte depth,
                        final ExtendedKey parent,
                        final byte[] childNumber,
                        final byte[] fingerprint,
                        final Boolean yParity) {
        this.key = X;
        this.version = version;
        this.chainCode = chainCode;
        this.depth = depth;
        this.parent = parent;
        this.childNumber = childNumber;
        this.fingerprint = fingerprint;
        this.yParity = yParity;
    }

    public static class Builder {
        BigInteger key;
        byte[] chainCode;
        int version;
        byte depth;
        ExtendedKey parent;
        byte[] childNumber;
        byte[] fingerprint;
        private Boolean yParity;

        public Builder setKey(BigInteger key) {
            this.key = key;
            return this;
        }

        public Builder setChainCode(byte[] chainCode) {
            this.chainCode = chainCode;
            return this;
        }

        public Builder setVersion(int version) {
            this.version = version;
            return this;
        }

        public Builder setDepth(byte depth) {
            this.depth = depth;
            return this;
        }

        public Builder setParent(ExtendedKey parent) {
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

        public Builder setYParity(Boolean yParity) {
            this.yParity = yParity;
            return this;
        }

        public ExtendedPrivateKey buildPrivateKey() {
            assert key != null;
            assert chainCode != null;
            assert yParity == null;

            return new ExtendedPrivateKey(this);
        }

        public ExtendedPublicKey buildPublicKey() {
            assert key != null;
            assert chainCode != null;
            assert yParity != null;

            return new ExtendedPublicKey(this);
        }
    }
}
