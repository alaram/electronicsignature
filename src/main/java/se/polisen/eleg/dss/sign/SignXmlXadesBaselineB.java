package se.polisen.eleg.dss.sign;

import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.JKSSignatureToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.AppleSignatureToken;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

import java.util.List;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.security.KeyStore;

/**
 * This is a test client to sign a document, the requirements are:
 * 1 - Create a document and sign it with the help of DSS implementation using XaDES
 * 2 - Timestamp the signed document from step 1.
 * 3 - Verify XaDES signature with the help of DSS XaDES library
 *
 * @author Alan Ramos
 */
public class SignXmlXadesBaselineB {

    private static final DSSDocument toSignDocument = new FileDocument("src/main/resources/xml_example.xml");

    private SignXmlXadesBaselineB() { }

    public static void main(String[] args) throws Exception {

        // Verify that JKSSignatureToken has keys to use for JKSSignature signature
        verifyJKSSignatureTokenKeyRing();

        //JKSSignatureTokenSignature();
        //MSCAPISignatureTokenSignature();
        //AppleSignatureTokenSignature();
    }

    private static void JKSSignatureTokenSignature() throws IOException {

        InputStream is = null;
        try {
            is = new FileInputStream("src/main/resources/keystore.jks");
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }

        try (JKSSignatureToken signingToken = new JKSSignatureToken(is, new KeyStore.PasswordProtection("dss-password".toCharArray()))) {

            List<DSSPrivateKeyEntry> list = signingToken.getKeys();
            // Choose the right private key entry from store.
            // The index will depend of the number of the certificates on your card.
            System.out.println(list.size());
            DSSPrivateKeyEntry privateKey = list.get(0);

            // Preparing parameters for the XAdES signature
            XAdESSignatureParameters parameters = new XAdESSignatureParameters();

            // We choose the level of the signature (-B, -T, -LT, -LTA).
            // This levels intend to facilitate interoperability and encompass the life cycle of XAdES signature
            // 1. B-B level provides requirements for the incorporation of signed and some unsigned qualifying
            // properties when the signature is generated.
            // 2. B-T level provides requirements for the generation and inclusion, for an existing signature,
            // of a trusted token proving that the signature itself actually existed at a certain date and time.
            // 3. LT level provides requirements for the incorporation of all the material required for validating
            // the signature in the signature document. This level aims to tackle the long term availability of the
            // validation material.
            // 4. B-LTA level provides requirements for the incorporation of electronic time-stamps that allow
            // validation of the signature long time after its generation. This level aims to tackle the long term
            // availability and integrity of the validation material.

            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            //parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
            //parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
            //parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

            // We choose the type of the signature packaging (ENVELOPED, ENVELOPING, DETACHED).
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

            // We set the digest algorithm to use with the signature algorithm. You must use the
            // same parameter when you invoke the method sign on the token. The default value is SHA256
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // We set the signing certificate
            parameters.setSigningCertificate(privateKey.getCertificate());

            // We set the certificate chain
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Create common certificate verifier
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

            // Create XAdES service for signature
            XAdESService service = new XAdESService(commonCertificateVerifier);

            // Get the SignedInfo XML segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

            // We invoke the service to sign the document with the signature value obtained in the previous step.
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            // save the signed document on the filesystem
            signedDocument.save("target/signedXmlXadesMSCapi.xml");
        }
    }
    private static void MSCAPISignatureTokenSignature() throws IOException {
        try (MSCAPISignatureToken signingToken = new MSCAPISignatureToken()) {

            List<DSSPrivateKeyEntry> list = signingToken.getKeys();
            // Choose the right private key entry from store.
            // The index will depend of the number of the certificates on your card.
            System.out.println(list.size());
            DSSPrivateKeyEntry privateKey = list.get(0);

            // Preparing parameters for the XAdES signature
            XAdESSignatureParameters parameters = new XAdESSignatureParameters();

            // We choose the level of the signature (-B, -T, -LT, -LTA).
            // This levels intend to facilitate interoperability and encompass the life cycle of XAdES signature
            // 1. B-B level provides requirements for the incorporation of signed and some unsigned qualifying
            // properties when the signature is generated.
            // 2. B-T level provides requirements for the generation and inclusion, for an existing signature,
            // of a trusted token proving that the signature itself actually existed at a certain date and time.
            // 3. LT level provides requirements for the incorporation of all the material required for validating
            // the signature in the signature document. This level aims to tackle the long term availability of the
            // validation material.
            // 4. B-LTA level provides requirements for the incorporation of electronic time-stamps that allow
            // validation of the signature long time after its generation. This level aims to tackle the long term
            // availability and integrity of the validation material.

            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            //parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
            //parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
            //parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

            // We choose the type of the signature packaging (ENVELOPED, ENVELOPING, DETACHED).
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

            // We set the digest algorithm to use with the signature algorithm. You must use the
            // same parameter when you invoke the method sign on the token. The default value is SHA256
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // We set the signing certificate
            parameters.setSigningCertificate(privateKey.getCertificate());

            // We set the certificate chain
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Create common certificate verifier
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

            // Create XAdES service for signature
            XAdESService service = new XAdESService(commonCertificateVerifier);

            // Get the SignedInfo XML segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

            // We invoke the service to sign the document with the signature value obtained in the previous step.
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            // save the signed document on the filesystem
            signedDocument.save("target/signedXmlXadesMSCapi.xml");
        }
    }
    private static void AppleSignatureTokenSignature() throws IOException {
        try (AppleSignatureToken signingToken = new AppleSignatureToken()) {

            List<DSSPrivateKeyEntry> list = signingToken.getKeys();
            // Choose the right private key entry from store.
            // The index will depend of the number of the certificates on your card.
            System.out.println(list.size());
            DSSPrivateKeyEntry privateKey = list.get(0);

            // Preparing parameters for the XAdES signature
            XAdESSignatureParameters parameters = new XAdESSignatureParameters();

            // We choose the level of the signature (-B, -T, -LT, -LTA).
            // This levels intend to facilitate interoperability and encompass the life cycle of XAdES signature
            // 1. B-B level provides requirements for the incorporation of signed and some unsigned qualifying
            // properties when the signature is generated.
            // 2. B-T level provides requirements for the generation and inclusion, for an existing signature,
            // of a trusted token proving that the signature itself actually existed at a certain date and time.
            // 3. LT level provides requirements for the incorporation of all the material required for validating
            // the signature in the signature document. This level aims to tackle the long term availability of the
            // validation material.
            // 4. B-LTA level provides requirements for the incorporation of electronic time-stamps that allow
            // validation of the signature long time after its generation. This level aims to tackle the long term
            // availability and integrity of the validation material.

            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            //parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
            //parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
            //parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

            // We choose the type of the signature packaging (ENVELOPED, ENVELOPING, DETACHED).
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

            // We set the digest algorithm to use with the signature algorithm. You must use the
            // same parameter when you invoke the method sign on the token. The default value is SHA256
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // We set the signing certificate
            parameters.setSigningCertificate(privateKey.getCertificate());

            // We set the certificate chain
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Create common certificate verifier
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

            // Create XAdES service for signature
            XAdESService service = new XAdESService(commonCertificateVerifier);

            // Get the SignedInfo XML segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

            // We invoke the service to sign the document with the signature value obtained in the previous step.
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            // save the signed document on the filesystem
            signedDocument.save("target/signedXmlXadesMSCapi.xml");
        }
    }

    public static void verifyJKSSignatureTokenKeyRing() throws Exception {

        try (InputStream is = SignXmlXadesBaselineB.class.getClassLoader().getResourceAsStream("keystore.jks")) {
            if (is == null) {
                throw new FileNotFoundException("keystore.jks not found in classpath");
            }
        //}

        //try (InputStream is = new FileInputStream("src/main/resources/keystore.jks");
             JKSSignatureToken jksSignatureToken = new JKSSignatureToken(is, new KeyStore.PasswordProtection("dss-password".toCharArray())); //{

            DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

            List<DSSPrivateKeyEntry> keys = jksSignatureToken.getKeys();
            for (DSSPrivateKeyEntry key : keys) {

                CertificateToken certificate = key.getCertificate();
                System.out.println(dateFormat.format(certificate.getNotAfter()) + ": " + certificate.getSubject().getCanonical());
                CertificateToken[] certificateChain = key.getCertificateChain();
                for (CertificateToken x509Certificate : certificateChain) {
                    System.out.println("/t" + dateFormat.format(x509Certificate.getNotAfter()) + ": " + x509Certificate.getSubject().getCanonical());
                }
            }
            System.out.println("DONE");
        }
    }
}