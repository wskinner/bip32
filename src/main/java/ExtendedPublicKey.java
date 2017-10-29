import org.bouncycastle.math.ec.ECPoint;

public class ExtendedPublicKey extends ExtendedKey {
    public static int testnet_version = 0x043587CF;
    public static int mainnet_version = 0x0488B21E;

    protected ExtendedPublicKey(Builder builder) {
        super(builder);
    }
}
