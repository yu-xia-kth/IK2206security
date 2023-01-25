import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
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

    //init cert
    public static Handshake init(String usercert,String cacert,String key,Socket socket) throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
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
        handshake.setServerEncrypter(encrypter);
        handshake.setServerDecrypter(decrypter);
        System.out.println("Step 1: Recv Client Cert");
        //接收客户端证书
        HandshakeMessage cert = HandshakeMessage.recv(socket);
        if(cert != null) {
            result = handshake.doServerHandshake(cert, certificate);
            if(!result) {
                System.out.println("Server Hand Error");
            }
        }
        recvDigest.update(cert.getBytes());
        System.out.println("Step 2: Send Server Cert");
        //发送服务端证书到客户端
        HandshakeMessage handshakeMessage = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        handshakeMessage.putParameter("Certificate",Handshake.encode(encryptCertificate.xcf.getEncoded()));
        handshakeMessage.send(socket);
        sendDigest.update(handshakeMessage.getBytes());
        System.out.println("Step 3: Recv Session");
        //接收session
        HandshakeMessage session = HandshakeMessage.recv(socket);
        if(session != null) {
            result = handshake.doServerHandshake(session, certificate);
            if(!result) {
                System.out.println("Server Hand Error");
            }
        }
        recvDigest.update(session.getBytes());
        System.out.println("Step 4: Send Server Finish");
        //发送完成的消息
        handshake.doServerFinish(sendDigest);

        System.out.println("Step 5: Recv Client Finish");
        //接收完成验证的消息
        HandshakeMessage finish = HandshakeMessage.recv(socket);
        if(finish != null) {
            result = handshake.doServerHandshake(finish, certificate);
            if(!result) {
                System.out.println("Server Hand Error");
            }
        }
        //比较发送的和接收的消息是否一致

        if(!result) {
            throw new RuntimeException("Server Hand Error");
        }
        return handshake;
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) {
        parseArgs(args);
        ServerSocket serverSocket = null;

        int port = Integer.parseInt(arguments.get("port"));
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
        Handshake handshake = null;
        try {
            String usercert = arguments.get("usercert");
            String cacert = arguments.get("cacert");
            String key = arguments.get("key");
            handshake = init(usercert,cacert,key,socket);
            System.out.println("connect client success");
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.printf("Error accepting connection on cert");
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
