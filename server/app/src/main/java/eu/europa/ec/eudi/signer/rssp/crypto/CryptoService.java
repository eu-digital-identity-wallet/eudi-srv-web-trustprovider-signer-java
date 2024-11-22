/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.rssp.crypto;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.rssp.common.config.AuthProperties;
import eu.europa.ec.eudi.signer.rssp.common.config.CSCProperties;
import eu.europa.ec.eudi.signer.rssp.common.config.CryptoConfig;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.entities.Credential;
import eu.europa.ec.eudi.signer.rssp.entities.Certificate;
import eu.europa.ec.eudi.signer.rssp.ejbca.EJBCAService;
import eu.europa.ec.eudi.signer.rssp.entities.SecretKey;
import eu.europa.ec.eudi.signer.rssp.hsm.HSMService;
import eu.europa.ec.eudi.signer.rssp.repository.ConfigRepository;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

@Component
public class CryptoService {

    private static final Logger logger = LoggerFactory.getLogger(CryptoService.class);

    private final CertificateGenerator generator;
    private final CryptoSigner cryptoSigner;
    private final CryptoConfig config;
    private final PemConverter pemConverter;
    private final HSMService hsmService;
    private final EJBCAService ejbcaService;
    private final AuthProperties authProperties;
    private static final int IVLENGTH = 12;

    public CryptoService(@Autowired ConfigRepository configRep, @Autowired CSCProperties cscProperties,
            @Autowired HSMService hsmService, @Autowired EJBCAService ejbcaService,
            @Autowired AuthProperties authProperties) throws Exception {
        this.config = cscProperties.getCrypto();
        this.cryptoSigner = new CryptoSigner();
        this.generator = new CertificateGenerator(config);
        this.pemConverter = new PemConverter(config);
        this.hsmService = hsmService;
        this.ejbcaService = ejbcaService;
        this.authProperties = authProperties;

        char[] passphrase = authProperties.getDbEncryptionPassphrase().toCharArray();
        byte[] saltBytes = Base64.getDecoder().decode(authProperties.getDbEncryptionSalt());

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(passphrase, saltBytes, 65536, 256);
        Key key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        List<SecretKey> secretKeys = configRep.findAll();
        if (secretKeys.isEmpty()) {
            // generates a secret key to wrap the private keys from the HSM
            byte[] secretKeyBytes = this.hsmService.initSecretKey();

            byte[] iv = new byte[IVLENGTH];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);

            // encrypts the secret key before saving it in the db
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec algSpec = new GCMParameterSpec(128, iv);
            c.init(Cipher.ENCRYPT_MODE, key, algSpec);
            byte[] encryptedSecretKeyBytes = c.doFinal(secretKeyBytes);

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedSecretKeyBytes.length);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedSecretKeyBytes);

            // saves in the db
            SecretKey sk = new SecretKey(byteBuffer.array());
            configRep.save(sk);
        } else {
            // loads the encrypted key from the database
            SecretKey sk = secretKeys.get(0);
            byte[] encryptedSecretKeyBytes = sk.getSecretKey();

            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedSecretKeyBytes);
            byte[] iv = new byte[IVLENGTH];
            byteBuffer.get(iv);
            byte[] encryptedSecretKey = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedSecretKey);

            // decrypts the secret key
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec algSpec = new GCMParameterSpec(128, iv);
            c.init(Cipher.DECRYPT_MODE, key, algSpec);
            byte[] secretKeyBytes = c.doFinal(encryptedSecretKey);

            // loads the decrypted key to the HSM
            this.hsmService.setSecretKey(secretKeyBytes);
        }
    }

    public static void savePublicKeyHSM(String owner, Credential credential, BigInteger modulus,
            BigInteger public_exponent) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pKeySpec = new RSAPublicKeySpec(modulus, public_exponent);
        RSAPublicKey pk = (RSAPublicKey) keyFactory.generatePublic(pKeySpec);
        credential.setPublicKeyHSM(pk.getEncoded());
    }

    /**
     * Function that allows to create a new certificate and keypair.
     * It requires the usage of a HSM and an EJBCA
     * Throws an exception if it can't create a key pair using the HSM
     * Throws an exception if it can't create a certificate using the EJBCA
     * 
     * @param owner       the id of the user that owns this credential
     * @param givenName   the given name of the user that owns this credential
     *                    (used
     *                    to create the certificate)
     * @param surname     the surname of the user that owns this credential (used
     *                    to
     *                    create the certificate)
     * @param subjectDN   name of the subject, used in the certificate
     * @param alias       the name by which the credential will be associated
     * @param countryCode the contryCode of the user (from the VP Token), that will
     *                    determine which CA will sign the certificate
     * @return the credential created
     * @throws Exception
     */
    public Credential createCredential(String owner, String givenName, String surname, String subjectDN,
            String alias, String countryCode) throws Exception {

        Credential credential = new Credential();

        byte[][] keysValues = generateKeyPair(owner);
        byte[] privKeyValues = keysValues[0];
        byte[] modulus = keysValues[1];
        BigInteger ModulusBI = new BigInteger(1, modulus);
        byte[] public_exponent = keysValues[2];
        BigInteger PublicExponentBI = new BigInteger(1, public_exponent);

        List<X509Certificate> EJBCACertificates = generateCertificates(owner, ModulusBI, PublicExponentBI,
                givenName, surname, subjectDN, alias, countryCode, privKeyValues);

        X509Certificate ejbcaCert = EJBCACertificates.get(0);
        List<Certificate> certs = new ArrayList<>();
        if (EJBCACertificates.size() > 1) {
            List<X509Certificate> ejbcaCertificateChain = EJBCACertificates.subList(1, EJBCACertificates.size());
            for (X509Certificate x509Certificate : ejbcaCertificateChain) {
                Certificate cert = new Certificate();
                cert.setCertificate(pemConverter.certificateToString(x509Certificate));
                cert.setCredential(credential);
                certs.add(cert);
            }
        }

        savePublicKeyHSM(owner, credential, ModulusBI, PublicExponentBI);
        credential.setKeyAlgorithmOIDs(generator.getKeyAlgorithmOIDs());
        credential.setKeyBitLength(generator.getKeyBitLength());
        credential.setECDSACurveOID(generator.getECSDACurveOID());
        credential.setKeyEnabled(true);
        credential.setCertificate(pemConverter.certificateToString(ejbcaCert));
        credential.setPrivateKeyHSM(privKeyValues);
        credential.setAlias(alias);
        credential.setOwner(owner);
        credential.setSubjectDN(ejbcaCert.getSubjectX500Principal().toString());
        credential.setIssuerDN(ejbcaCert.getIssuerX500Principal().getName());
        credential.setValidFrom(ejbcaCert.getNotBefore().toString());
        credential.setValidTo(ejbcaCert.getNotAfter().toString());
        credential.setCertificateChains(certs);
        return credential;
    }

    /**
     * Function that allows to create a key pair
     * Exception: if the algorithm define in the application.yml for key creation is
     * not supported
     * Exception: if the hsm could not generate a key pair
     * 
     * @param owner the user that requested the key creation
     * @return the private key wrapped, the modulus of the public key and the public
     *         exponent
     */
    public byte[][] generateKeyPair(String owner) throws ApiException {
        if (!this.config.getKeyAlgorithm().equals("RSA")) {
            String logMessage = SignerError.CredentialAliasAlreadyExists.getCode()
                    + "(generateKeyPair in CryptoService.class) The algorithm " + this.config.getKeyAlgorithm()
                    + " for key pair creation is not supported by the current implementation.";
            logger.error(logMessage);
            LoggerUtil.logsUser(this.authProperties.getDatasourceUsername(),
                    this.authProperties.getDatasourcePassword(), 0, owner, 3, "");
            throw new ApiException(SignerError.AlgorithmNotSupported, "The algorithm " + this.config.getKeyAlgorithm()
                    + " for key pair creation is not supported by the current implementation.");
        }

        try {
            return this.hsmService.generateRSAKeyPair(this.config.getKeySize());
        } catch (Exception e) { // Fail to generate the RSA Key Pair
            String logMessage = SignerError.FailedCreatingKeyPair.getCode()
                    + "(generateKeyPair in CryptoService.class) "
                    + SignerError.FailedCreatingKeyPair.getDescription() + ": " + e.getMessage();
            logger.error(logMessage);
            LoggerUtil.logsUser(this.authProperties.getDatasourceUsername(),
                    this.authProperties.getDatasourcePassword(), 0, owner, 3, "");
            throw new ApiException(SignerError.FailedCreatingKeyPair, SignerError.FailedCreatingKeyPair.getDescription());
        }
    }

    /**
     * Function that allows to create a certificate signed by a CA
     * Exception: if the EJBCA fails to create a certificate
     * 
     * @param owner            the user that requested the issuance of the
     *                         certificate
     * @param ModulusBI        the modulus of the public key
     * @param PublicExponentBI the public exponents of the public key
     * @param givenName        the given name of the owner of the certificate to
     *                         create
     * @param surname          the surname of the owner of the certificate to create
     * @param subjectCN        the subject of the certificate
     * @param alias            the alias of the credential for which it is going to
     *                         be created the certificate
     * @param countryCode      the country code of the owner
     * @param privKeyValues    the private key wrapped
     * @return the list of the Certificates (includes the certificate created and
     *         the certificate chain)
     */
    public List<X509Certificate> generateCertificates(String owner, BigInteger ModulusBI, BigInteger PublicExponentBI,
            String givenName, String surname, String subjectCN, String alias, String countryCode,
            byte[] privKeyValues) throws ApiException {

        try {
            // Create a certificate Signing Request for the keys
            byte[] csrInfo = generator.generateCertificateRequestInfo(ModulusBI, PublicExponentBI, givenName, surname, subjectCN, countryCode);
            byte[] signature = hsmService.signDTBSwithRSAPKCS11(privKeyValues, csrInfo);
            PKCS10CertificationRequest certificateHSM = generator.generateCertificateRequest(csrInfo, signature);

            String certificateString = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                    new String(Base64.getEncoder().encode(certificateHSM.getEncoded())) + "\n" +
                    "-----END CERTIFICATE REQUEST-----";

            // Makes a request to the CA
            List<X509Certificate> certificateAndCertificateChain = this.ejbcaService.certificateRequest(certificateString, countryCode);
            if(!validateCertificateFromCA(certificateAndCertificateChain, givenName, surname, subjectCN, countryCode)){
                throw new Exception("Certificates received from CA are not valid");
            }
            return certificateAndCertificateChain;
        } catch (Exception e) {
            String logMessage = SignerError.FailedCreatingCertificate.getCode()
                    + "(generateCertificates in CryptoService.class) "
                    + SignerError.FailedCreatingCertificate.getDescription() + ": " + e.getMessage();
            logger.error(logMessage);
            LoggerUtil.logsUser(this.authProperties.getDatasourceUsername(),
                    this.authProperties.getDatasourcePassword(), 0, owner, 1, "");
            throw new ApiException(SignerError.FailedCreatingCertificate,
                    SignerError.FailedCreatingKeyPair.getDescription());
        }
    }

    public boolean validateCertificateFromCA(List<X509Certificate> certificatesAndCertificateChain, String givenName, String surname, String subjectCN, String countryCode){
        if(certificatesAndCertificateChain.isEmpty()){
            return false;
        }

        String expectedIssuerSubjectCN = this.ejbcaService.getCertificateAuthorityNameByCountry(countryCode);

        X509Certificate certificate = certificatesAndCertificateChain.get(0);
        X500Principal subjectX500Principal = certificate.getSubjectX500Principal();
        X500Name x500SubjectName = new X500Name(subjectX500Principal.getName());
        X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
        X500Name x500IssuerName = new X500Name(issuerX500Principal.getName());

        RDN[] rdnGivenName = x500SubjectName.getRDNs(BCStyle.GIVENNAME);
        if(rdnListContainsValue(rdnGivenName, givenName)){
            return false;
        }

        RDN[] rdnSurname = x500SubjectName.getRDNs(BCStyle.SURNAME);
        if(rdnListContainsValue(rdnSurname, surname)){
            return false;
        }

        RDN[] rdnSubjectCN = x500SubjectName.getRDNs(BCStyle.CN);
        if(rdnListContainsValue(rdnSubjectCN, subjectCN)){
            return false;
        }

        RDN[] rdnCountry = x500SubjectName.getRDNs(BCStyle.C);
        if(rdnListContainsValue(rdnCountry, countryCode)){
            return false;
        }


        // System.out.println(expectedIssuerSubjectCN);
        RDN[] rdnIssuerSubjectCN = x500IssuerName.getRDNs(BCStyle.CN);
        return !rdnListContainsValue(rdnIssuerSubjectCN, expectedIssuerSubjectCN);
    }

    // Verifies if the rdnListFromCertificate doesn't have the value
    // if the value is not present, returns true
    public static boolean rdnListContainsValue(RDN[] rdnListFromCertificate, String value){
        if(rdnListFromCertificate == null)
            return true;

        for (RDN rdn : rdnListFromCertificate) {
            String name = IETFUtils.valueToString(rdn.getFirst().getValue());
            // System.out.println(name);
            if(name.equals(value))
                return false;
        }

        return true;
    }

    /**
     * Function that allows to sign the data of a pdf document
     * 
     * @param dataToSignB64       the data of the pdf
     * @param pemCertificate      the certificate to use to sign the pdf
     * @param pemCertificateChain the certificate chain associated to the
     *                            certificate
     * @param signingKeyWrapped   the signing key created previously by the user
     * @param signingAlgo         the signing algorithm
     * @param signingAlgoParams   the signe parameters
     * @return the value of the signature
     */
    public String signWithPemCertificate(String dataToSignB64, String pemCertificate, List<String> pemCertificateChain,
            byte[] signingKeyWrapped, String signingAlgo, String signingAlgoParams) {
        // TODO validate signingAlgo against the signing algo params
        final X509Certificate x509Certificate = pemToX509Certificate(pemCertificate);

        List<X509Certificate> x509CertificateChain = new ArrayList<>();
        for (String s : pemCertificateChain) {
            x509CertificateChain.add(pemToX509Certificate(s));
        }

        try {
            byte[] dataToSign = Base64.getDecoder().decode(dataToSignB64);
            final byte[] bytes = cryptoSigner.signData(dataToSign, x509Certificate, x509CertificateChain,
                    signingKeyWrapped, this.hsmService);
            return Base64.getEncoder().encodeToString(bytes);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw new ApiException(SignerError.FailedSigningData, e);
        }
    }

    /**
     * Unmarshall the PEM string (Base64) form of the certificate into an
     * X509Certificate object
     * 
     * @param pemCertificate
     * @return proper X509Certificate object
     */
    public X509Certificate pemToX509Certificate(String pemCertificate) {
        try {
            return pemConverter.stringToCertificate(pemCertificate);
        } catch (IOException | CertificateException e) {
            throw new ApiException(SignerError.FailedUnmarshallingPEM, e);
        }
    }

    public boolean isCertificateExpired(X509Certificate x509Certificate) {
        return generator.isCertificateExpired(x509Certificate);
    }
}
