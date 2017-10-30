# Hierarchical Deterministic Bitcoin Wallets
Compliant implementation of the [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) 
specification for Hierarchical Deterministic Wallets.

## Usage
Using maven:
```bash
mvn package
```

## Examples
Importing a Base58Check serialized wallet:
```java
String base58PrivateKey = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
ExtendedKeyPair extendedPrivateKey = ExtendedKeyPair.parseBase58Check(base58PrivateKey);
```

Serializing an extended key:
```java
String base58PrivateKey = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
ExtendedKeyPair extendedPrivateKey = ExtendedKeyPair.parseBase58Check(base58PrivateKey);

String serializedPublicKey = extendedPrivateKey.serializePub();
String serializedPrivateKey = extendedPrivateKey.serializePriv();
```

Generating ancestors of an extended key:
```java
ExtendedKeyPair masterKey = Bip32.generateMasterKey(new byte[]{0, 0, 0, 0});
ExtendedKeyPair childKey = masterKey.generate("m/0/2147483647H/1");
```

## Notes
I have included [Bitcoinj](https://github.com/bitcoinj/bitcoinj) out of laziness.
To avoid pulling in Bitcoinj, I would need to implement Base58 in this library.
