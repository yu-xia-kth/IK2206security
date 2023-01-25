import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {

    Key key;
    /*
     * Constructor to create an instance for encryption/decryption with a public key.
     * The public key is given as a X509 certificate.
     */
    public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
        X509Certificate XCF=handshakeCertificate.getCertificate();
        key= XCF.getPublicKey();
    }

    /*
     * Constructor to create an instance for encryption/decryption with a private key.
     * The private key is given as a byte array in PKCS8/DER format.
     */

    public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        key=keyFactory.generatePrivate(keySpec);
    }

    /*
     * Decrypt byte array with the key, return result as a byte array
     */
    public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher HandshakeMessage = Cipher.getInstance("RSA");
        HandshakeMessage.init(Cipher.DECRYPT_MODE,key);
        return HandshakeMessage.doFinal(ciphertext);
    }

    /*
     * Encrypt byte array with the key, return result as a byte array
     */
    public byte [] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher HandshakeMessage = Cipher.getInstance("RSA");
        HandshakeMessage.init(Cipher.ENCRYPT_MODE,key);
        return HandshakeMessage.doFinal(plaintext);
    }
}