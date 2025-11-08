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

package eu.europa.ec.eudi.signer.csc.error;

import eu.europa.ec.eudi.signer.common.ApiError;

/**
 * Enum holding all the error codes and descriptions
 */
public enum CSCInvalidRequest implements ApiError {

  MissingBearer("The request is missing a required parameter, includes an invalid parameter "
      + "value, includes a parameter more than once, or is otherwise malformed."),

  InvalidPageToken("Invalid parameter pageToken"),

  // From CSC Spec:
  // If a user-specific service authorization is present, it SHALL NOT be allowed
  // to use this
  // parameter to obtain the list of credentials associated to a different user.
  // The remote service SHALL return an error in such case.
  // NOTE 1: User-specific service authorization include the following authType:
  // “basic”, “digest” and “oauth2code”.
  // Non-user-specific service authorization include the following authType:
  // “external”, “TLS” or “oauth2client”.
  NonNullUserId("userID parameter MUST be null"),

  // Should not be needed since we use user-specified authorization
  InvalidUserId("Invalid parameter userID"),

  // Credential errors
  // From 10.5 of the CSC Spec for credentials/info
  MissingCredentialId("Missing (or invalid type) string parameter credentialID"),
  InvalidCredentialId("Invalid parameter credentialID"),
  InvalidCertificatesParameter("Invalid parameter certificates"),

  // SignHash Errors
  // From 11.9 of the CSC for signatures/signHash
  MissingSAD("Missing (or invalid type) string parameter SAD"),
  InvalidSAD("Invalid parameter SAD"),
  InvalidHashArray("Missing (or invalid type) array parameter hash"),
  InvalidHashParameter("Invalid Base64 hash string parameter"),
  HashNotAuthorizedBySAD("Hash is not authorized by the SAD"),
  MissingSignAlgo("Missing (or invalid type) string parameter signAlgo"),
  MissingSignAlogParams("Missing (or invalid type) string parameter signAlgoParams"),
  // Missing or not String “hashAlgo” parameter when “signAlgo” is equal to
  // “1.2.840.113549.1.1.1”
  MissingHashAlgo("Missing (or invalid type) string parameter hashAlgo"),
  InvalidHashAlgo("Invalid parameter hashAlgo"),
  InvalidSignAlgo("Invalid parameter signAlgo"),
  InvalidClientData("Invalid parameter clientData"),
  // Invalid “hash” length
  InvalidHashLength("Invalid digest value length"),
  InvalidOTP("The OTP is invalid"),
  SADExpired("SAD expired"),

  // credential/authorize
  MissingNumSignatures("Missing (or invalid type) integer parameter numSignatures"),
  InvalidNumSignatures("Invalid value for parameter numSignatures"),
  TooHighNumSignatures("Numbers of signatures is too high"),

  InvalidPin("The PIN is invalid"),
  LockedPin("PIN locked"),

  Invalid("Signing certificate 'O=[organization],CN=[common_name]' is expired");

  private String description;

  CSCInvalidRequest(String description) {
    this.description = description;
  }

  public String getCode() {
    // All API errors in the CSC spec return invalid_request
    return "invalid_request";
  }

  public int getHttpCode() {
    // All API errors in the CSC spec return http status 400
    return 400;
  }

  public String getDescription() {
    return description;
  }
}
