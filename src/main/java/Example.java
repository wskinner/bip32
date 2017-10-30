public class Example {

    public static void main(String[] args) {
        // Example 1
        String base58PrivateKey = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        ExtendedKeyPair extendedPrivateKey = ExtendedKeyPair.parseBase58Check(base58PrivateKey);

        // Example 2
        base58PrivateKey = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        extendedPrivateKey = ExtendedKeyPair.parseBase58Check(base58PrivateKey);

        String serializedPublicKey = extendedPrivateKey.serializePub();
        String serializedPrivateKey = extendedPrivateKey.serializePriv();

        // Example 3
        ExtendedKeyPair masterKey = Bip32.generateMasterKey(new byte[]{0, 0, 0, 0});
        ExtendedKeyPair childKey = masterKey.generate("m/0/2147483647H/1");
    }
}
