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

package eu.europa.ec.eudi.signer.rssp.common.error;

import eu.europa.ec.eudi.signer.common.ApiError;

/**
 * Enum holding all the Signer error codes and descriptions
 */
public enum SignerError implements ApiError {
        UserNotFound("user_not_found", "User not found", 404), // 404 not found

        CredentialAliasAlreadyExists("credential_alias_already_exists",
                        "The credential alias chosen is not valid. The aliases must be unique.", 400), // 404 conflit

        CredentialNotFound("credential_not_found",
                        "No credential was found matching the alias given.", 404), // 404 not found

        AlgorithmNotSupported("algorithm_not_supported", "The algorithm chosen is not supported", 500),

        FailedCreatingKeyPair("failed_creating_key_pair", "An error occurred while generating the key pair", 500),

        FailedCreatingCertificate("failed_creating_certificate",
                        "An error occurred while generating certificate", 500), // 500 internal server error

        UnexpectedError("unexpected_error", "Unexpected Error", 500),

        UnexpectedOperationType("unexpected_operation_type",
                        "Operation Type used in the Presentation Request is not supported", 500),

        FailedConnectionToVerifier("failed_connection_to_verifier",
                        "An error occurred when trying to connect to the Verifier", 404), // 404 not found

        MissingDataInResponseVerifier("missing_data_in_response_verifier",
                        "The response received from the verifier is missing required information.", 500),

        ConnectionVerifierTimedOut("connection_verifier_timed_out",
                        "The process of waiting for the response from the verifier timed out",
                        504), // 504 gateway timeout

        AccessCredentialDenied("access_credential_denied", "The acces to the credential requested was denied.", 401), // 401
                                                                                                                      // unauthorized

        FailedToValidateSAD("failed_to_validate_sad", "The SAD receive in the request was not validated.", 500), // 500
                                                                                                                 // internal
                                                                                                                 // server
                                                                                                                 // error

        UnexpectedValidationError("unexpected_validiation_error",
                        "An unexpected validation error occurred in the RSSP.", 500), // 500 internal server error

        FailedUnmarshallingPEM("failed_unmarshalling_pem",
                        "An error occurred while converting a PEM string to  key or certificate.", 500), // 500 internal
                                                                                                         // server error

        FailedSigningData("failed_signing",
                        "An error occurred while trying to sign data with a certificate and private key.", 500), // 500
                                                                                                                 // internal
                                                                                                                 // server
                                                                                                                 // error

        // Errors while validating the VP Token:
        FailedToValidateVPToken("failed_validate_vp_token", "The validation step of the VP Token failed.", 500), // 500
                                                                                                                 // internal
                                                                                                                 // server
                                                                                                                 // error

        PresentationSubmissionMissingData("presentation_submission_missing_data",
                        "The validation of the VP Token failed, because the validation of presentation submission failed.",
                        432),

        StatusVPTokenInvalid("status_vptoken_invalid", "The status present in the VP Token is invalid.", 433),

        CertificateIssuerAuthInvalid("certificate_issuerauth_invalid",
                        "The certificate present in the IssuerAuth in the VP Token is invalid.", 434),

        SignatureIssuerAuthInvalid("signature_issuerauth_invalid",
                        "The signature present in the IssuerAuth in the VP Token is invalid.", 435),

        DocTypeMSODifferentFromDocuments("doctype_mso_different_from_documents",
                        "The DocType in the MSO is different from the DocType in the document of the VPToken", 436),

        IntegrityVPTokenNotVerified("integrity_vptoken_not_verified",
                        "The digest of the IssuerSignedItem are not equal to the digests in MSO. Couldn't verify the integrity.",
                        437),

        ValidityInfoInvalid("validity_info_vptoken_invalid", "The ValidityInfo from the VPToken was not valid.", 438),

        // UserNotOver18("user_not_over_18", "User must be over 18.", 439),

        VPTokenMissingValues("vptoken_missing_requested_values", "The VPToken is missing values requested.", 440),

        SigningNotAuthorized("signing_not_authorized", "The signing operation was not authorized.", 500);

        private final String code;
        private final int httpCode;
        private final String desc;

        SignerError(String code, String desc, int httpCode) {
                this.code = code;
                this.desc = desc;
                this.httpCode = httpCode;
        }

        @Override
        public String getCode() {
                return code;
        }

        @Override
        public int getHttpCode() {
                return httpCode;
        }

        @Override
        public String getDescription() {
                return desc;
        }

        /**
         * Returns a formatted message that could be used to return an error message as
         * a response to the API requests.
         * The followed format would be, for example, [ user_not_found ] User not found
         * 
         * @return a formatted message
         */
        public String getFormattedMessage() {
                return "[" + this.code + "] " + this.desc;
        }
}
