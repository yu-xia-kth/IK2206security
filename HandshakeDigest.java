import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {

    MessageDigest messageDigest;
    public HandshakeDigest() throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance("SHA-256");
    }
    public void update(byte[] input) {
        messageDigest.update(input);
    }
    public byte[] digest() {
        return messageDigest.digest();
    }
};