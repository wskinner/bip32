import com.subgraph.orchid.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class Vector1Test {
    byte[] seed = null;
    ExtendedKeyPair masterKey;

    @Before
    public void setup() {
        seed = Hex.decode("000102030405060708090a0b0c0d0e0f");
        masterKey = Bip32.generateMasterKey(seed);
    }

    @Test
    public void testSet1() {
        // Using Test vector 1

        String base58Encoded = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

        ExtendedKeyPair expectedPrivKey = ExtendedKeyPair.parseBase58Check(base58Encoded);
        ExtendedKeyPair actualPrivKey = Bip32.generateMasterKey(seed);
        assertEquals(expectedPrivKey.serializePriv(), actualPrivKey.serializePriv());

        ExtendedKeyPair expectedPubKey = ExtendedKeyPair.parseBase58Check("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
        assertEquals(expectedPubKey.serializePub(), actualPrivKey.serializePub());
    }

    @Test
    public void testSet2() {
        String expectedPub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
        String expectedPriv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";

        ExtendedKeyPair expectedKeyPair = ExtendedKeyPair.parseBase58Check(expectedPriv);
        String chainId = "/0";
        ExtendedKeyPair keyPair = masterKey.generate(chainId);
//        assertEquals(expectedPriv, keyPair.serializePriv());
        assertEquals(expectedPub, keyPair.serializePub());
    }


}
