import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.Base58;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class Bip32Test {
    private Bip32 bip32;

    @Before
    public void setup() {
        bip32 = new Bip32();
    }

    @Test
    public void testSer32() {
        int i = 0;
        byte[] expected = {0, 0, 0, 0};
        assertArrayEquals(expected, bip32.ser32(i));

        i = Integer.MAX_VALUE;
        byte[] expected2 = {(byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertArrayEquals(expected2, bip32.ser32(i));

        i = Integer.MIN_VALUE;
        byte[] expected3 = {(byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        assertArrayEquals(expected3, bip32.ser32(i));
    }

    @Test
    public void testSer256() {
        // positive number
        // The twos complement representation of this number is the number with a 0 prepended. This
        // means the byte length will be 33, so the ser256 function should strip off that byte.
        String hexString = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        BigInteger bignum = new BigInteger(hexString, 16);
        byte[] unsignedRep = Bip32.ser256(bignum);
        assertEquals(hexString, Hex.encodeHexString(unsignedRep));

        // extending to 32 bytes
        hexString = "0000000000000000000000000000000000000000000000000000000000000000";
        bignum = new BigInteger("00", 16);
        unsignedRep = Bip32.ser256(bignum);
        assertEquals(hexString, Hex.encodeHexString(unsignedRep));

        // negative number
        hexString = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        bignum = new BigInteger("-1");
        unsignedRep = Bip32.ser256(bignum);
        assertEquals(hexString, Hex.encodeHexString(unsignedRep));
    }

    @Test
    public void testSerP() {

    }

    @Test
    public void testParse256() {
        byte[] bytes = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        BigInteger bignum = bip32.parse256(bytes);
        assertEquals(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE), bignum);
        assertArrayEquals(bytes, Bip32.ser256(bip32.parse256(bytes)));

    }

    @Test
    public void testParse() {
        String base58PrivateKey = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        ExtendedPrivateKey extendedPrivateKey = ExtendedPrivateKey.parse(base58PrivateKey);

        assertEquals(base58PrivateKey, extendedPrivateKey.toString());
    }

    @Test
    public void testMasterKeyGeneration() {
        byte[] seed = new byte[0];
        try {
            seed = Hex.decodeHex("000102030405060708090a0b0c0d0e0f");
        } catch (DecoderException e) {
            e.printStackTrace();
            fail();
        }
        String base58Encoded = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        ExtendedPrivateKey expectedPrivateKey = ExtendedPrivateKey.parse(base58Encoded);
        byte[] expectedBytes = base58Encoded.getBytes();

        ExtendedPrivateKey actualPrivateKey = bip32.generateMasterKey(seed);
        byte[] actualBytes = actualPrivateKey.toString().getBytes();
        assertArrayEquals(expectedBytes, actualBytes);
    }
}
