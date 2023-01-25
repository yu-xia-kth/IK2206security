import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.*;
import java.util.Base64;

public class HandshakeCertificate {

    private static final String CERTIFICATE_TYPE = "X.509";
    CertificateFactory factory;
    X509Certificate xcf;

    HandshakeCertificate(InputStream instream) throws CertificateException {
        factory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        xcf=(X509Certificate)factory.generateCertificate(instream);
    }

    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        byte[] input= Base64.getDecoder().decode(certbytes);
        factory=CertificateFactory.getInstance(CERTIFICATE_TYPE);
        ByteArrayInputStream bis=new ByteArrayInputStream(input);
        xcf=(X509Certificate)factory.generateCertificate(bis);
    }

    public byte[] getBytes() throws CertificateEncodingException {
        return Base64.getEncoder().encode(xcf.getEncoded());
    }

    public X509Certificate getCertificate() {
        return xcf;
    }

    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        X509Certificate caCertificate=cacert.getCertificate();
        caCertificate.checkValidity();
        caCertificate.verify(caCertificate.getPublicKey());
    }

    public String getCN() {
        String DN=xcf.getSubjectX500Principal().getName();
        String CN=DN.substring(DN.indexOf("CN=")+3, DN.indexOf(",OU"));
        return CN;
    }

    public String getEmail() {
        Certificate cf;
        cf=(Certificate)xcf;
        String content=cf.toString();
        String DN=xcf.getSubjectX500Principal().getName();
        String CN=DN.substring(DN.indexOf("CN=")+3, DN.indexOf(",OU"));
        String email=content.substring(content.indexOf("Subject: EMAILADDRESS=")+22, content.indexOf(CN)-5);
        return email;
    }
}