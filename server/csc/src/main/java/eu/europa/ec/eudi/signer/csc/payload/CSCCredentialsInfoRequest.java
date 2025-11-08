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

package eu.europa.ec.eudi.signer.csc.payload;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Body for request of credentials/info - information about a specific  credential record of credential IDs
 * From section 11.5 of the CSC API V_1.0.4.0 spec
 */
public class CSCCredentialsInfoRequest {
    // REQUIRED
    // The unique identifier associated to the credential (the alias).
    @NotBlank(message = "Missing CredentialID")
    private String credentialID;

    // OPTIONAL
    // none | single | chain
    // Specifies which certificates from the certificate chain shall be returned in certs/certificates.
    // • “none”: No certificate SHALL be returned.
    // • “single”: Only the end entity certificate SHALL be returned.
    // • “chain”: The full certificate chain SHALL be returned.
    // The default value is “single”, so if the parameter is omitted then the method will only return the end entity certificate.
    @Pattern(regexp = "^(none|single|chain)$", message = "Invalid parameter certificates")
    private String certificates;

    // OPTIONAL
    // Request to return various parameters containing information from the end entity certificate.
    // This is useful in case the signature application wants to retrieve some details of the certificate without having to decode it first.
    // The default value is “false”, so if the parameter is omitted then the  information will not be returned.
    private boolean certInfo = false;

    // OPTIONAL
    // Request to return various parameters containing information on the authorization mechanisms supported by this credential (PIN and OTP groups).
    // The default value is “false”, so if the parameter is omitted then the information will not be returned.
    private boolean authInfo = false;

    // OPTIONAL
    // The lang as defined in the Input parameter table in section 11.1.
    @Pattern(regexp = "^[a-zA-Z]{2}(-[a-zA-Z]{2})?$", message = "Invalid language code")
    private String lang;

    // OPTIONAL
    // String The clientData as defined in the Input parameter table in section 8.3.2.
    private String clientData;

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public String getCertificates() {
        return certificates;
    }

    public void setCertificates(String certificates) {
        this.certificates = certificates;
    }

    public boolean isCertInfo() {
        return certInfo;
    }

    public void setCertInfo(boolean certInfo) {
        this.certInfo = certInfo;
    }

    public boolean isAuthInfo() {
        return authInfo;
    }

    public void setAuthInfo(boolean authInfo) {
        this.authInfo = authInfo;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }
}
