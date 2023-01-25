import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public class SessionKey{
    private KeyGenerator key_generate;
    private SecureRandom Random_num = new SecureRandom();
    private SecretKey secret_key;

    public SessionKey(int length) throws NoSuchAlgorithmException {
        key_generate = KeyGenerator.getInstance("AES");
        key_generate.init(length, Random_num);
        secret_key = key_generate.generateKey();
    }

    public SessionKey(byte[] keybytes){
        secret_key = new SecretKeySpec(keybytes,"AES");
    }

    public SecretKey getSecretKey(){
        return secret_key;
    }
    public byte[] getKeyBytes() {
        return secret_key.getEncoded();
    }
}