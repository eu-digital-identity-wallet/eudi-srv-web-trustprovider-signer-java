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

package eu.europa.ec.eudi.signer.rssp.security.openid4vp;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.common.error.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.rssp.ejbca.EJBCAService;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import COSE.AlgorithmID;
import id.walt.mdoc.COSECryptoProviderKeyInfo;
import id.walt.mdoc.SimpleCOSECryptoProvider;
import id.walt.mdoc.cose.COSESign1;
import id.walt.mdoc.dataelement.EncodedCBORElement;
import id.walt.mdoc.dataretrieval.DeviceResponse;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.issuersigned.IssuerSignedItem;
import id.walt.mdoc.mso.DigestAlgorithm;
import id.walt.mdoc.mso.MSO;
import id.walt.mdoc.mso.ValidityInfo;
import kotlinx.datetime.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VPValidator {
    private static final Logger log = LoggerFactory.getLogger(VPValidator.class);
    private final JSONObject verifiablePresentation;
    private final String presentationDefinitionInputDescriptorsId;
    private final String presentationDefinitionId;
    private final String keyID;
    private final EJBCAService ejbcaService;

    public VPValidator(JSONObject vp, String presentation_definition_id,
            String presentation_definition_input_descriptors_id, EJBCAService ejbcaService) {
        this.verifiablePresentation = vp;
        this.presentationDefinitionId = presentation_definition_id;
        this.presentationDefinitionInputDescriptorsId = presentation_definition_input_descriptors_id;
        this.keyID = "keyID";
        this.ejbcaService = ejbcaService;
    }

    /**
     * Function that allows verification of the Presentation Submission in the
     * Response from the Verifier.
     * This function verifies if the Presentation Submission has the required
     * definition_id, which should be equal to the one defined in the Presentation
     * Definition in the Request.
     * This function verifies if the Descriptor_Map from the Presentation Submission
     * also contains the requested value, in a supported format.
     * 
     * @return the position in the array documents of the vp_token where the
     *         requested Verifiable Presentation is located.
     */
    private int validatePresentationSubmission() throws VerifiablePresentationVerificationException, JSONException {

        JSONObject presentation_submission = this.verifiablePresentation.getJSONObject("presentation_submission");

        if (!presentation_submission.getString("definition_id").equals(this.presentationDefinitionId)) {
            log.error("'definition_id' in 'presentation_submission' is not the expected.");
            throw new VerifiablePresentationVerificationException(SignerError.PresentationSubmissionMissingData,
                  "definition_id in presentation_submission is not the expected.",
                  VerifiablePresentationVerificationException.Default);
        }

        JSONArray descriptor_map = presentation_submission.getJSONArray("descriptor_map");

        JSONObject descriptor_map_response = IntStream.range(0, descriptor_map.length())
                .mapToObj(descriptor_map::getJSONObject)
                .filter(jobj -> jobj.getString("id").equals(this.presentationDefinitionInputDescriptorsId))
                .findFirst()
                .orElse(null);

        if (descriptor_map_response == null) {
            log.error("No descriptor_map in the presentation_submission contains information about the requested VP.");
            throw new VerifiablePresentationVerificationException(SignerError.PresentationSubmissionMissingData,
                  "No descriptor_map in the presentation_submission contains information about the requested VP.",
                  VerifiablePresentationVerificationException.Default);
        }

        if (!descriptor_map_response.getString("format").equals("mso_mdoc")) {
            log.error("The current program only supports vp_tokens in the format mso_mdoc.");
            throw new VerifiablePresentationVerificationException(SignerError.PresentationSubmissionMissingData,
                  "The current program only supports vp_tokens in the format mso_mdoc.",
                  VerifiablePresentationVerificationException.Default);
        }

        return getPathIntValue(descriptor_map_response);
    }

    /**
     * Function that allows to obtained the position from the 'path' value from the
     * descriptor_map
     * 
     * @param descriptor_map_response The JSON Object from the JSON Array
     *                                descriptor_map from where to obtained the path
     *                                value
     * @return The position presented in the 'path' value in the descriptor_map
     */
    private static int getPathIntValue(JSONObject descriptor_map_response)
            throws VerifiablePresentationVerificationException {
        int pos;
        String path = descriptor_map_response.getString("path");

        if (path.equals("$")) {
            pos = 0;
        } else {
            Matcher matcher = Pattern.compile("\\d+").matcher(path);
            if (matcher.find()) {
                pos = Integer.parseInt(matcher.group());
            } else
                pos = -1;
        }

        if (pos == -1) {
            log.error("The path value from presentation_submission is not valid.");
            throw new VerifiablePresentationVerificationException(SignerError.FailedToValidateVPToken,
                  "The path value from presentation_submission is not valid.",
                  VerifiablePresentationVerificationException.Default);
        }

        return pos;
    }

    /**
     * Function that loads the vp_token from the Verifiable Presentation to the
     * class DeviceResponse from the package id.walt.mdoc.dataretrieval
     */
    private DeviceResponse loadVpTokenToDeviceResponse() {
        String deviceResponse = this.verifiablePresentation.getJSONArray("vp_token").getString(0);
        byte[] decodedBytes = Base64.getUrlDecoder().decode(deviceResponse);
        StringBuilder hexString = new StringBuilder();
        for (byte b : decodedBytes) {
            hexString.append(String.format("%02x", b));
        }
        return DeviceResponse.Companion.fromCBORHex(hexString.toString());
    }

    // [0]: the certificate from the issuer signed
    // [1...]: the Certificate list
    private List<X509Certificate> getAndValidateCertificateFromIssuerAuth(MDoc document) throws Exception {
        COSESign1 issuerAuth = document.getIssuerSigned().getIssuerAuth();
        CertificateFactory factory = CertificateFactory.getInstance("x.509");
        assert issuerAuth != null;
        InputStream in = new ByteArrayInputStream(Objects.requireNonNull(issuerAuth.getX5Chain()));
        X509Certificate cert = (X509Certificate) factory.generateCertificate(in);

        X509Certificate issuerCertificate = this.ejbcaService.searchForIssuerCertificate(cert.getIssuerX500Principal());
        if (issuerCertificate == null) {
			log.error("Issuer ({}) of the VPToken is not trustworthy.", cert.getIssuerX500Principal().getName());
            throw new Exception("Issuer (" + cert.getIssuerX500Principal().getName() + ") of the VPToken is not trustworthy.");
        }

        issuerCertificate.verify(issuerCertificate.getPublicKey());
        issuerCertificate.checkValidity();

        cert.verify(issuerCertificate.getPublicKey());
        cert.checkValidity();

        List<X509Certificate> certificateChain = new ArrayList<>();
        certificateChain.add(cert);
        certificateChain.add(issuerCertificate);
        return certificateChain;
    }

    private SimpleCOSECryptoProvider getSimpleCOSECryptoProvider(X509Certificate certificate,
            List<X509Certificate> certificateChain) {
        COSECryptoProviderKeyInfo keyInfo = new COSECryptoProviderKeyInfo(
                this.keyID, AlgorithmID.ECDSA_256, certificate.getPublicKey(),
                null, Collections.singletonList(certificate), certificateChain);
        return new SimpleCOSECryptoProvider(Collections.singletonList(keyInfo));
    }

    private static void validateValidityInfoElements(MDoc document, ValidityInfo validityInfo, java.time.Instant notBefore, java.time.Instant notAfter) throws VerifiablePresentationVerificationException {
        Instant validity_info_signed = validityInfo.getSigned().getValue();

        if (!document.verifyValidity()) { // This function verifies the Validity, based on validity info given in the MSO.
            log.error("Failed the ValidityInfo verification step: the ValidFrom or the ValidUntil from the IssuerAuth is later than the current time.");
            throw new VerifiablePresentationVerificationException(SignerError.ValidityInfoInvalid,
                    "Failed the ValidityInfo verification step: the ValidFrom or the ValidUntil from the IssuerAuth is later than the current time.",
                    VerifiablePresentationVerificationException.Default);
        }

        Instant certNotBefore = new Instant(notBefore);
        Instant certNotAfter = new Instant(notAfter);
        if (validity_info_signed.compareTo(certNotAfter) > 0 || validity_info_signed.compareTo(certNotBefore) < 0) {
            log.error("Failed the ValidityInfo verification step: the Signed in the IssuerAuth is not valid.");
            throw new VerifiablePresentationVerificationException(SignerError.ValidityInfoInvalid,
                  "Failed the ValidityInfo verification step: the Signed in the IssuerAuth is not valid.", VerifiablePresentationVerificationException.Default);
        }
    }

    private Map<Integer, String> addSignatureLog(MDoc document, Map<Integer, String> logs) {
        StringBuilder strBuilder = new StringBuilder();
        assert document.getIssuerSigned().getIssuerAuth() != null;
        byte[] signature = document.getIssuerSigned().getIssuerAuth().getSignatureOrTag();
        strBuilder.append("Signature Value: ").append(Base64.getEncoder().encodeToString(signature)).append(" | ");
        byte[] hash = document.getIssuerSigned().getIssuerAuth().getPayload();
        strBuilder.append("Payload Hash: ").append(Base64.getEncoder().encodeToString(hash));
        logs.put(8, strBuilder.toString());
        return logs;
    }

    private Map<Integer, String> addIntegrityLog(MSO mso, MDoc document, List<EncodedCBORElement> nameSpaces,
            Map<Integer, String> logs) {
        StringBuilder integrity_log = new StringBuilder();

        String digestAlg = mso.getDigestAlgorithm().getValue();
        integrity_log.append("DigestAlgorithm: ").append(digestAlg).append(" | ");

        Map<Integer, byte[]> valueDigests = mso.getValueDigestsFor(document.getDocType().getValue());
        DigestAlgorithm algs = null;
        if (digestAlg.equals("SHA-256")) {
            algs = DigestAlgorithm.SHA256;
        } else if (digestAlg.equals("SHA-512")) {
            algs = DigestAlgorithm.SHA512;
        }

        if (algs == null) {
            algs = DigestAlgorithm.SHA256;
        }

        List<IssuerSignedItem> items = document.getIssuerSignedItems(document.getDocType().getValue());

        for (int i = 0; i < items.size(); i++) {
            integrity_log.append("'").append(items.get(i).getElementIdentifier().getValue()).append("': ");
            int digestId = items.get(i).getDigestID().getValue().intValue();
            byte[] digest = valueDigests.get(digestId);
            byte[] digestObtained = MSO.Companion.digestItem(nameSpaces.get(i), algs);
            integrity_log.append("Received: ").append(Base64.getEncoder().encodeToString(digest)).append("; ");
            integrity_log.append("Calculated: ").append(Base64.getEncoder().encodeToString(digestObtained)).append(" | ");
        }

        logs.put(9, integrity_log.toString());
        return logs;
    }

    public MDoc loadAndVerifyDocumentForVP(Map<Integer, String> logs)
            throws VerifiablePresentationVerificationException {
        try {
            // Validate the Presentation Submission and get the Path from the
            // descriptor_map.
            int pos = validatePresentationSubmission();

            DeviceResponse vpToken = loadVpTokenToDeviceResponse();

            // Verify that the status in the vpToken is equal "success"
            if (vpToken.getStatus().getValue().intValue() != 0) {
                log.error("The vp_token's status is not equal to a successful status.");
                throw new VerifiablePresentationVerificationException(SignerError.StatusVPTokenInvalid,
                      "The vp_token's status is not equal to a successful status.",
                      VerifiablePresentationVerificationException.Default);
            }

            MDoc document = vpToken.getDocuments().get(pos);

            SimpleCOSECryptoProvider provider;
            X509Certificate certificateFromIssuerAuth;

            // Validate Certificate from the MSO header:
            try {
                List<X509Certificate> certificateList = getAndValidateCertificateFromIssuerAuth(document);
                certificateFromIssuerAuth = certificateList.get(0);
                List<X509Certificate> certificateChain = certificateList.subList(1, certificateList.size());
                provider = getSimpleCOSECryptoProvider(certificateFromIssuerAuth, certificateChain);
            } catch (Exception e) {
				log.error("The Certificate in issuerAuth is not valid. ({})", e.getMessage());
                throw new VerifiablePresentationVerificationException(SignerError.CertificateIssuerAuthInvalid,
                "The Certificate in issuerAuth is not valid. (" + e.getMessage() + ":" + e.getLocalizedMessage() + ")", VerifiablePresentationVerificationException.Default);
            }

            /*MSO mso = document.getMSO();


            if (!document.verifyCertificate(provider, this.keyID)) {
                log.error("Certificate in issuerAuth is not valid.");
                throw new VerifiablePresentationVerificationException(SignerError.CertificateIssuerAuthInvalid,
                      "Certificate in issuerAuth is not valid.", VerifiablePresentationVerificationException.Default);
            }

            // Verify the Digital Signature in the Issuer Auth
            if (!document.verifySignature(provider, this.keyID)) {
                log.error("The IssuerAuth Signature is not valid.");
                throw new VerifiablePresentationVerificationException(SignerError.SignatureIssuerAuthInvalid,
                      "The IssuerAuth Signature is not valid.", VerifiablePresentationVerificationException.Signature);
            }

            logs = addSignatureLog(document, logs);

            // Verify the "DocType" in MSO == "DocType" in Documents
            if (!document.verifyDocType()) {
                log.error("The DocType in the MSO is not equal to the DocType in documents.");
                throw new VerifiablePresentationVerificationException(SignerError.DocTypeMSODifferentFromDocuments,
                      "The DocType in the MSO is not equal to the DocType in documents.",
                      VerifiablePresentationVerificationException.Default);
            }

            assert mso != null;
            if (!mso.getDocType().getValue().equals(document.getDocType().getValue())) {
                log.error("The DocType in the MSO is not equal to the DocType in documents.");
                throw new VerifiablePresentationVerificationException(SignerError.DocTypeMSODifferentFromDocuments,
                      "The DocType in the MSO is not equal to the DocType in documents.",
                      VerifiablePresentationVerificationException.Default);
            }

            // Calcular o valor do digest de cada IssuerSignedItem do DeviceResponse e
            // verificar que os digests calculados são iguais ao dos MSO
            if (!document.verifyIssuerSignedItems()) {
                log.error("The digest of the IssuerSignedItems are not equal to the digests in MSO.");
                throw new VerifiablePresentationVerificationException(SignerError.IntegrityVPTokenNotVerified,
                      "The digest of the IssuerSignedItems are not equal to the digests in MSO.",
                      VerifiablePresentationVerificationException.Integrity);
            }

            assert document.getIssuerSigned().getNameSpaces() != null;
            List<EncodedCBORElement> nameSpaces = document.getIssuerSigned().getNameSpaces()
                    .get(document.getDocType().getValue());
            if (!mso.verifySignedItems(document.getDocType().getValue(), nameSpaces)) {
                log.error("The digest of the IssuerSignedItem are not equal to the digests in MSO.");
                throw new VerifiablePresentationVerificationException(SignerError.IntegrityVPTokenNotVerified,
                      "The digest of the IssuerSignedItem are not equal to the digests in MSO.",
                      VerifiablePresentationVerificationException.Integrity);
            }

            logs = addIntegrityLog(mso, document, nameSpaces, logs);

            // Verify the ValidityInfo:
            validateValidityInfoElements(document, mso.getValidityInfo(), certificateFromIssuerAuth.getNotBefore().toInstant(), certificateFromIssuerAuth.getNotAfter().toInstant());
             */
            return document;
        }
        catch (JSONException e){
			log.error("The JSON string contains unexpected errors ({}).", e.getMessage());
            throw new VerifiablePresentationVerificationException(SignerError.UnexpectedError, "The JSON string contains unexpected errors ("+e.getMessage()+").", VerifiablePresentationVerificationException.Default);
        }
        catch (Exception e){
			log.error("{} : {}", SignerError.UnexpectedError.getFormattedMessage(), e.getMessage());
            throw new VerifiablePresentationVerificationException(SignerError.UnexpectedError, e.getMessage(), VerifiablePresentationVerificationException.Default);
        }
    }
}
