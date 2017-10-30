import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class Vector2Test {
    byte[] seed = null;
    ExtendedKeyPair masterKey;

    @Before
    public void setup() {
        seed = Hex.decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
        masterKey = Bip32.generateMasterKey(seed);
    }

    @Test
    public void testSet1() {
        String expectedPub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
        String expectedPriv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
        assertEquals(expectedPub, masterKey.serializePub());
        assertEquals(expectedPriv, masterKey.serializePriv());
    }

    @Test
    public void testSet2() {
        String chainId = "m/0";
        ExtendedKeyPair childKey = masterKey.generate(chainId);
        String expectedPub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
        String expectedPriv = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt";
        assertEquals(expectedPub, childKey.serializePub());
        assertEquals(expectedPriv, childKey.serializePriv());
    }
}
