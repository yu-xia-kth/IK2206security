import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

//主要是这个方法
public class Handshake {

    HandshakeCrypto clientEncrypter;
    HandshakeCrypto serverEncrypter;

    HandshakeCrypto clientDecrypter;
    HandshakeCrypto serverDecrypter;

    Socket socket;

    SessionCipher sessionEncrypt;
    SessionCipher sessionDecrypt;

    public Handshake(Socket socket) {
        this.socket = socket;
    }

    public void setClientEncrypter(HandshakeCrypto clientEncrypter) {
        this.clientEncrypter = clientEncrypter;
    }

    public void setServerEncrypter(HandshakeCrypto serverEncrypter) {
        this.serverEncrypter = serverEncrypter;
    }

    public void setClientDecrypter(HandshakeCrypto clientDecrypter) {
        this.clientDecrypter = clientDecrypter;
    }

    public void setServerDecrypter(HandshakeCrypto serverDecrypter) {
        this.serverDecrypter = serverDecrypter;
    }

    public SessionCipher getSessionEncrypt() {
        return sessionEncrypt;
    }

    public SessionCipher getSessionDecrypt() {
        return sessionDecrypt;
    }

    public static String ENCODING = "UTF-8"; /* For converting between strings and byte arrays */

    //接收消息，接收消息进行消息的判断，
    public boolean doServerHandshake(HandshakeMessage hmsg, HandshakeCertificate ca_cert) {
        boolean result = true;
        if(hmsg.getType() == HandshakeMessage.MessageType.SESSION) {
            try{
                //接收到session消息，验证
                String SessionKey = hmsg.getParameter("SessionKey");
                String SessionIV = hmsg.getParameter("SessionIV");
                //服务端私钥解密
                byte[]key = this.serverDecrypter.decrypt(decode(SessionKey));
                byte[]iv = this.serverDecrypter.decrypt(decode(SessionIV));
                //验证通过，返回
                SessionKey sessionkey = new SessionKey(key);
                this.sessionEncrypt = new SessionCipher(sessionkey, iv);
                this.sessionEncrypt.getCipher().init(Cipher.ENCRYPT_MODE, sessionkey.getSecretKey(), new IvParameterSpec(iv));
                this.sessionDecrypt = new SessionCipher(sessionkey, iv);
                this.sessionDecrypt.getCipher().init(Cipher.DECRYPT_MODE, sessionkey.getSecretKey(), new IvParameterSpec(iv));
            }catch (Exception e){
                //如果验证失败的，直接退出，断开socket
                e.printStackTrace();
                result = false;
            }
        }else if(hmsg.getType() == HandshakeMessage.MessageType.CLIENTFINISHED){
            //发送消息，公钥解密
            String Digest = hmsg.getParameter("Signature");
            String Timestamp = hmsg.getParameter("TimeStamp");
            try{
                String time = new String(this.clientEncrypter.decrypt(decode(Timestamp)), ENCODING);
                //客户端公钥解密
                String message = new String(this.clientEncrypter.decrypt(decode(Digest)), ENCODING);
                System.out.println(time + ": On Finish");
            }catch (Exception e){
                e.printStackTrace();
                result = false;
            }
        }else if(hmsg.getType() == HandshakeMessage.MessageType.CLIENTHELLO){
            try{
                String Certificate = hmsg.getParameter("Certificate");
                HandshakeCertificate encryptCertificate = new HandshakeCertificate(Certificate.getBytes());
                encryptCertificate.verify(ca_cert);
                this.clientEncrypter = new HandshakeCrypto(encryptCertificate);
            }catch (Exception e){
                e.printStackTrace();
                result = false;
            }
        }
        return result;
    }

    public boolean doClientHandshake(HandshakeMessage hmsg, HandshakeCertificate ca_cert){
        boolean result = true;
        if(hmsg.getType() == HandshakeMessage.MessageType.SERVERFINISHED){
            //发送消息，公钥解密
            String Digest = hmsg.getParameter("Signature");
            String Timestamp = hmsg.getParameter("TimeStamp");
            try{
                String time = new String(this.serverEncrypter.decrypt(decode(Timestamp)), ENCODING);
                String message = new String(this.serverEncrypter.decrypt(decode(Digest)), ENCODING);
                System.out.println(time + ": On Finish");
            }catch (Exception e){
                e.printStackTrace();
                result = false;
            }
        }else if(hmsg.getType() == HandshakeMessage.MessageType.SERVERHELLO){
            try{
                String Certificate = hmsg.getParameter("Certificate");
                HandshakeCertificate encryptCertificate = new HandshakeCertificate(Certificate.getBytes());
                encryptCertificate.verify(ca_cert);
                this.serverEncrypter = new HandshakeCrypto(encryptCertificate);
            }catch (Exception e){
                e.printStackTrace();
                result = false;
            }
        }
        return result;
    }

    public void doSession(MessageDigest md) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        SessionKey sessionKey = new SessionKey(128);
        SessionCipher sessionCipher = new SessionCipher(sessionKey);
        HandshakeMessage session = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        session.putParameter("SessionKey",Handshake.encode(this.serverEncrypter.encrypt(sessionKey.getKeyBytes())));
        session.putParameter("SessionIV",Handshake.encode(this.serverEncrypter.encrypt(sessionCipher.getIVBytes())));
        this.sessionEncrypt = sessionCipher;
        this.sessionDecrypt = new SessionCipher(sessionKey, sessionCipher.getIVBytes());
        this.sessionDecrypt.getCipher().init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), new IvParameterSpec(this.sessionEncrypt.getIVBytes()));
        session.send(socket);
        md.update(session.getBytes());
    }

    public void doServerFinish(MessageDigest md) throws IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        HandshakeMessage hmsg = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String Timestamp = encode(this.serverDecrypter.encrypt(dateFormat.format(new Date()).getBytes(ENCODING)));
        hmsg.putParameter("TimeStamp",Timestamp);
        String Digest = encode(this.serverDecrypter.encrypt(md.digest()));
        hmsg.putParameter("Signature",Digest);
        hmsg.send(this.socket);
    }

    public void doClientFinish(MessageDigest md) throws IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        HandshakeMessage hmsg = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String Timestamp = encode(this.clientDecrypter.encrypt(dateFormat.format(new Date()).getBytes(ENCODING)));
        hmsg.putParameter("TimeStamp",Timestamp);
        String Digest = encode(this.clientDecrypter.encrypt(md.digest()));
        hmsg.putParameter("Signature",Digest);
        hmsg.send(this.socket);
    }

    public static String encode(byte[] data) {
        String encoded = Base64.getEncoder().encodeToString(data);
        return encoded;
    }

    public static byte[] decode(String data) {
        byte[] decoded = Base64.getDecoder().decode(data);
        return decoded;
    }
}
