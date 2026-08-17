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

package eu.europa.ec.eudi.signer.rssp.common.config;

import jakarta.validation.constraints.AssertTrue;

public class VerifierProperties {
    private String domain;
    private String presentationUrl;
    private String validationUrl;
    private String intendedUseId;
    private String registrationCertificateJwt;

    @AssertTrue(message = "Either 'intendedUseId' or 'registrationCertificateId' must be defined")
    private boolean isIntendedUseOrRegistrationCertificateValid() {
        return (intendedUseId != null && !intendedUseId.isBlank())
              || (registrationCertificateJwt != null && !registrationCertificateJwt.isBlank());
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getPresentationUrl() {
        return presentationUrl;
    }

    public void setPresentationUrl(String presentationUrl) {
        this.presentationUrl = presentationUrl;
    }

    public String getValidationUrl() {
        return validationUrl;
    }

    public void setValidationUrl(String validationUrl) {
        this.validationUrl = validationUrl;
    }

    public String getIntendedUseId() {
        return intendedUseId;
    }

    public void setIntendedUseId(String intendedUseId) {
        this.intendedUseId = intendedUseId;
    }

    public String getRegistrationCertificateJwt() {
        return registrationCertificateJwt;
    }

    public void setRegistrationCertificateJwt(String registrationCertificateJwt) {
        this.registrationCertificateJwt = registrationCertificateJwt;
    }
}
