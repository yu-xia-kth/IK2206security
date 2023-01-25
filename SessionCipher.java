import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {

    private Cipher cipher;
    private SessionKey sessionKey;
    private IvParameterSpec IV;
    public SessionCipher(SessionKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        sessionKey=key;
        byte[] ivbytes = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(ivbytes);
        IV = new IvParameterSpec(ivbytes);
        //IV = new IvParameterSpec(this.getRandomNonce());
        cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), IV);
    }
    public SessionCipher(SessionKey key, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        sessionKey=key;
        IV = new IvParameterSpec(ivbytes);
        //cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), IV);
    }
    public SessionKey getSessionKey() {
        return sessionKey;
    }
    public byte[] getIVBytes() {
        return IV.getIV();
    }

    public Cipher getCipher() {
        return cipher;
    }

    CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        CipherOutputStream openCipherOutputsteam = new CipherOutputStream(os, cipher);
        return openCipherOutputsteam;

    }
    CipherInputStream openDecryptedInputStream(InputStream inputstream) {
        CipherInputStream openCipherInputSteam = new CipherInputStream(inputstream,cipher);
        return openCipherInputSteam;
    }
    /*
    private byte[] getRandomNonce() {
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }*/
}