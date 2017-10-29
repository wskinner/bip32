import java.math.BigInteger;

public class ExtendedPublicKey {
    final BigInteger K;
    final byte[] c;

    public ExtendedPublicKey(BigInteger k, byte[] c) {
        K = k;
        this.c = c;
    }
}
