import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "usercert");
        arguments.setArgumentSpec("cacert", "cacert");
        arguments.setArgumentSpec("key", "key");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    public static Handshake init(String usercert,String cacert,String key,Socket socket) throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        boolean result = false;

        FileInputStream instream = new FileInputStream(cacert);
        HandshakeCertificate certificate = new HandshakeCertificate(instream);
        System.out.println("Load Cert Info:" + certificate.getCN() + " " + certificate.getEmail());

        Handshake handshake = new Handshake(socket);
        FileInputStream certInputStream = new FileInputStream(usercert);
        HandshakeCertificate encryptCertificate = new HandshakeCertificate(certInputStream);
        HandshakeCrypto encrypter = new HandshakeCrypto(encryptCertificate);
        /* Read private key from file and create private-key decrypter */
        FileInputStream keyInputStream = new FileInputStream(key);
        byte[] keybytes = keyInputStream.readAllBytes();
        HandshakeCrypto decrypter = new HandshakeCrypto(keybytes);
        MessageDigest sendDigest = MessageDigest.getInstance("SHA-256");
        MessageDigest recvDigest = MessageDigest.getInstance("SHA-256");
        handshake.setClientEncrypter(encrypter);
        handshake.setClientDecrypter(decrypter);
        System.out.println("Step 1: Send Client Cert");
        //发送客户端证书
        HandshakeMessage handshakeMessage = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        handshakeMessage.putParameter("Certificate",Handshake.encode(encryptCertificate.xcf.getEncoded()));
        handshakeMessage.send(socket);
        sendDigest.update(handshakeMessage.getBytes());
        System.out.println("Step 2: Recv Server Cert");
        //接收服务端证书
        HandshakeMessage cert = HandshakeMessage.recv(socket);
        if(cert != null) {
            result = handshake.doClientHandshake(cert, certificate);
            if(!result) {
                System.out.println("Server Hand Error");
            }
        }

        recvDigest.update(cert.getBytes());
        System.out.println("Step 3: Send Session");
        //发送session
        handshake.doSession(sendDigest);
        System.out.println("Step 4: Recv Server Finish");
        //接收完成的消息
        HandshakeMessage finish = HandshakeMessage.recv(socket);
        if(finish != null) {
            result = handshake.doClientHandshake(finish, certificate);
            if(!result) {
                System.out.println("Server Hand Error");
            }
        }

        //发送完成
        System.out.println("Step 5: Send Client Finish");
        handshake.doClientFinish(sendDigest);

        if(!result) {
            throw new RuntimeException("Server Hand Error");
        }
        return handshake;
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) {
        Socket socket = null;

        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        Handshake handshake = null;
        try {
            String usercert = arguments.get("usercert");
            String key = arguments.get("key");
            String cacert = arguments.get("cacert");
            handshake = init(usercert,cacert,key,socket);
            System.out.println("connect server success");
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.printf("Can't connect to server on cert");
            System.exit(1);
        }
        try {
            InputStream socketIn = handshake.getSessionDecrypt().openDecryptedInputStream(socket.getInputStream());
            OutputStream socketOut = handshake.getSessionEncrypt().openEncryptedOutputStream(socket.getOutputStream());
            Forwarder.forwardStreams(System.in, System.out, socketIn, socketOut, socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}
