import static org.junit.Assert.assertEquals;

class BaseTest {
    byte[] seed = null;
    ExtendedKeyPair masterKey;

    void validate(String expectedPub, String expectedPriv, String chainId) {
        ExtendedKeyPair childKeyPriv = masterKey.generate(chainId);
        ExtendedKeyPair childKeyNeutered = childKeyPriv.neuter();

        assertEquals(expectedPub, childKeyNeutered.serializePub());
        assertEquals(expectedPub, childKeyPriv.serializePub());
        assertEquals(expectedPriv, childKeyPriv.serializePriv());
    }
}
