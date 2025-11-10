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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.crypto.keys.IKeysService;
import eu.europa.ec.eudi.signer.rssp.util.CertificateUtils;
import org.bouncycastle.cms.CMSSignedData;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Utility for signing data like document hashes
 */
@Service
public class CryptoSigner {
    private final IKeysService keysService;

    public CryptoSigner(@Autowired IKeysService keysService) {
        this.keysService = keysService;
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
                                         byte[] signingKeyWrapped, String signingAlgo, String signingAlgoParams) throws ApiException  {
        X509Certificate x509Certificate = CertificateUtils.stringToCertificate(pemCertificate);

        List<X509Certificate> x509CertificateChain = new ArrayList<>();
        for (String s : pemCertificateChain)
            x509CertificateChain.add(CertificateUtils.stringToCertificate(s));

        try {
            byte[] dataToSign = Base64.getDecoder().decode(dataToSignB64);
            final byte[] bytes = signData(dataToSign, x509Certificate, x509CertificateChain, signingKeyWrapped);
            return Base64.getEncoder().encodeToString(bytes);
        } catch (Exception e) {
            throw new ApiException(SignerError.FailedSigningData, e);
        }
    }

    /**
     * Cryptographically sign the given data with the supplied signature and private
     * key
     *
     * @param data               data to sign (usually a document hash)
     * @return signature for provided data
     */

    private DSSMessageDigest getMessageDigestFromByteArray(byte[] data) throws IOException {
        final MessageDigest digest = DSSUtils.getMessageDigest(DigestAlgorithm.SHA256);
        InputStream inputStream = new ByteArrayInputStream(data);
        byte[] b = new byte[4096];
        int count;
        while ((count = inputStream.read(b)) > 0) {
            digest.update(b, 0, count);
        }
		return new DSSMessageDigest(DigestAlgorithm.SHA256, digest.digest());
    }

    private byte[] signData(byte[] data, final X509Certificate signingCertificate, List<X509Certificate> certificateChain, byte[] signingKey) throws Exception {
        DSSMessageDigest messageDigest = getMessageDigestFromByteArray(data);

        /*PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);*/

        CertificateVerifier cv = new CommonCertificateVerifier();
        ExternalCMSService padesCMSGeneratorService = new ExternalCMSService(cv);

        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(new CertificateToken(signingCertificate));
        List<CertificateToken> certChainToken = new ArrayList<>();
        for (X509Certificate cert : certificateChain) {
            certChainToken.add(new CertificateToken(cert));
        }
        signatureParameters.setCertificateChain(certChainToken);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);

        // Create DTBS (data to be signed) using the message-digest of a PDF signature
        // byte range obtained from a client
        ToBeSigned dataToSign = padesCMSGeneratorService.getDataToSign(messageDigest, signatureParameters);

        // Sign the DTBS using a private key connection or remote-signing service
        byte[] signatureHSM = this.keysService.sign(signingKey, dataToSign.getBytes());

        SignatureValue signatureValue = new SignatureValue();
        signatureValue.setAlgorithm(SignatureAlgorithm.RSA_SHA256);
        signatureValue.setValue(signatureHSM);

        // Create a CMS signature using the provided message-digest, signature parameters and the signature value
        CMSSignedDocument cmsSignature = padesCMSGeneratorService.signMessageDigest(messageDigest, signatureParameters, signatureValue);
        CMSSignedData signedData = cmsSignature.getCMSSignedData();
        return signedData.getEncoded();
    }
}
