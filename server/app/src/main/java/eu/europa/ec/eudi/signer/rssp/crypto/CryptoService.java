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

import eu.europa.ec.eudi.signer.rssp.common.config.KeysProperties;
import eu.europa.ec.eudi.signer.rssp.crypto.certificates.CertificateSigningRequestGenerator;
import eu.europa.ec.eudi.signer.rssp.crypto.certificates.CertificatesDTO;
import eu.europa.ec.eudi.signer.rssp.crypto.certificates.ICertificateIssuer;
import eu.europa.ec.eudi.signer.rssp.crypto.keys.IKeysService;
import eu.europa.ec.eudi.signer.rssp.crypto.keys.KeyPairDTO;
import eu.europa.ec.eudi.signer.rssp.util.CertificateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.entities.Credential;
import eu.europa.ec.eudi.signer.rssp.entities.Certificate;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

@Component
public class CryptoService {
    private static final Logger logger = LoggerFactory.getLogger(CryptoService.class);
    private final CertificateSigningRequestGenerator generator;
    private final LoggerUtil loggerUtil;
    private final IKeysService keysService;
    private final ICertificateIssuer certificateService;
    private final KeysProperties keysProperties;

    public CryptoService(@Autowired KeysProperties keysProperties, @Autowired IKeysService iKeysService, @Autowired ICertificateIssuer iCertificateService, @Autowired LoggerUtil loggerUtil) {
        this.keysProperties = keysProperties;
        this.generator = new CertificateSigningRequestGenerator();
        this.loggerUtil = loggerUtil;
        this.keysService = iKeysService;
        this.certificateService = iCertificateService;
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
     * @param countryCode the countryCode of the user (from the VP Token), that will
     *                    determine which CA will sign the certificate
     * @return the credential created
     */
    public Credential createCredential(String owner, String givenName, String surname, String subjectDN, String countryCode) throws Exception {
        Credential credential = new Credential();
        KeyPairDTO keysValues;
        try {
            keysValues = this.keysService.generateKeyPair();
        }
        catch (ApiException e){
            loggerUtil.logsUser(0, owner, 3, "");
            throw e;
        }
        credential.setPublicKeyHSM(keysValues.publicKey().getEncoded());
        credential.setPrivateKeyHSM(keysValues.encryptedPrivateKey());

        CertificatesDTO certificateAndChain = generateCertificates(owner, keysValues.publicKey(), givenName, surname, subjectDN, countryCode, keysValues.encryptedPrivateKey());

        List<Certificate> certs = new ArrayList<>();
        List<X509Certificate> chain = certificateAndChain.certificateChain();
        if (chain.size() > 1) {
            for (X509Certificate x509Certificate : chain) {
                Certificate cert = new Certificate();
                cert.setCertificate(CertificateUtils.certificateToString(x509Certificate));
                cert.setCredential(credential);
                certs.add(cert);
            }
        }
        credential.setKeyAlgorithmOIDs(this.keysProperties.getKeyAlgorithmsOIDs());
        credential.setKeyBitLength(this.keysProperties.getKeySize());
        credential.setECDSACurveOID(null);
        credential.setKeyEnabled(true);
        credential.setCertificate(CertificateUtils.certificateToString(certificateAndChain.signingCertificate()));

        credential.setOwner(owner);
        credential.setSubjectDN(certificateAndChain.signingCertificate().getSubjectX500Principal().toString());
        credential.setIssuerDN(certificateAndChain.signingCertificate().getIssuerX500Principal().getName());
        credential.setValidFrom(certificateAndChain.signingCertificate().getNotBefore().toString());
        credential.setValidTo(certificateAndChain.signingCertificate().getNotAfter().toString());
        credential.setCertificateChains(certs);
        return credential;
    }

    /**
     * Function that allows to create a certificate signed by a CA
     * Exception: if the EJBCA fails to create a certificate
     *
     * @param owner            the user that requested the issuance of the
     *                         certificate
     * @param publicKey        the public key
     * @param givenName        the given name of the owner of the certificate to
     *                         create
     * @param surname          the surname of the owner of the certificate to create
     * @param subjectCN        the subject of the certificate
     * @param countryCode      the country code of the owner
     * @param privKeyValues    the private key wrapped
     * @return the list of the Certificates (includes the certificate created and
     * the certificate chain)
     */
    private CertificatesDTO generateCertificates(String owner, PublicKey publicKey, String givenName, String surname,
                                                String subjectCN, String countryCode, byte[] privKeyValues) throws ApiException {
        try {
            // Create a certificate Signing Request for the keys
            byte[] csrInfo = this.generator.generateCertificateRequestInfo(publicKey, givenName, surname, subjectCN, countryCode);
            byte[] csrSignature = this.keysService.sign(privKeyValues, csrInfo);
            String certificateSigningRequest = this.generator.generateCertificateRequest(csrInfo, csrSignature);
			return this.certificateService.issueCertificate(certificateSigningRequest, countryCode, givenName, surname, subjectCN);
        } catch (Exception e) {
			logger.error("{}: {}", SignerError.FailedCreatingCertificate.getFormattedMessage(), e.getMessage());
            loggerUtil.logsUser(0, owner, 1, "");
            throw new ApiException(SignerError.FailedCreatingCertificate, SignerError.FailedCreatingKeyPair.getDescription());
        }
    }


    /**
     * Unmarshall the PEM string (Base64) form of the certificate into an
     * X509Certificate object
     */
    public X509Certificate pemToX509Certificate(String pemCertificate) throws ApiException {
        return CertificateUtils.stringToCertificate(pemCertificate);
    }

    public boolean isCertificateExpired(X509Certificate x509Certificate) {
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        Date now = calendar.getTime();
        return x509Certificate.getNotAfter().before(now);
    }
}
