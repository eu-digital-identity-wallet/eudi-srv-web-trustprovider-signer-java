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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import eu.europa.ec.eudi.signer.rssp.hsm.HSMService;

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

/**
 * Utility for signing data like document hashes
 */
public class CryptoSigner {

    /**
     * Cryptographically sign the given data with the supplied signature and private
     * key
     *
     * @param data               data to sign (usually a document hash)
     * @param signingCertificate certificate with which to sign the hash (contains
     *                           the public key)
     * @param signingKey         private key paired to the public key in the signing
     *                           certificate
     * @return signature for provided data
     */

    public byte[] signData(byte[] data, final X509Certificate signingCertificate,
            List<X509Certificate> certificateChain, final byte[] signingKey, HSMService hsmService) throws Exception {

        final MessageDigest digest = DSSUtils.getMessageDigest(DigestAlgorithm.SHA256);
        InputStream inputStream = new ByteArrayInputStream(data);
        byte[] b = new byte[4096];
        int count;
        while ((count = inputStream.read(b)) > 0) {
            digest.update(b, 0, count);
        }
        DSSMessageDigest messageDigest = new DSSMessageDigest(DigestAlgorithm.SHA256, digest.digest());

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);

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
        byte[] signatureHSM = hsmService.signDTBSwithRSAPKCS11(signingKey, dataToSign.getBytes());

        SignatureValue signatureValue = new SignatureValue();
        signatureValue.setAlgorithm(SignatureAlgorithm.RSA_SHA256);
        signatureValue.setValue(signatureHSM);

        // Create a CMS signature using the provided message-digest, signature
        // parameters and the signature value
        CMSSignedDocument cmsSignature = padesCMSGeneratorService.signMessageDigest(messageDigest, signatureParameters,
                signatureValue);
        CMSSignedData signedData = cmsSignature.getCMSSignedData();
        signedData.getSignerInfos().getSigners()
                .forEach(x -> System.out.println(x.getEncryptionAlgOID() + " & " + x.getDigestAlgOID())); // sha256WithRSAEncryption
                                                                                                          // &
        System.out.println(signedData.getSignedContentTypeOID()); // data
        for (AlgorithmIdentifier alg : signedData.getDigestAlgorithmIDs()) { // sha-256
            System.out.println(alg.toASN1Primitive().toString());
        }

        return cmsSignature.getCMSSignedData().getEncoded();
    }

    /**
     * Verfies the signed data
     * 
     * @param signedData
     * @return
     * @throws CMSException
     * @throws IOException
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    public boolean verifSignData(final byte[] signedData)
            throws CMSException, IOException, OperatorCreationException, CertificateException {
        // TODO remove this or pass in the certs
        ByteArrayInputStream bIn = new ByteArrayInputStream(signedData);
        ASN1InputStream aIn = new ASN1InputStream(bIn);
        CMSSignedData s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));
        aIn.close();
        bIn.close();
        Store certs = s.getCertificates();
        SignerInformationStore signers = s.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        SignerInformation signer = c.iterator().next();
        Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
        Iterator<X509CertificateHolder> certIt = certCollection.iterator();
        X509CertificateHolder certHolder = certIt.next();
		return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
	}

}
