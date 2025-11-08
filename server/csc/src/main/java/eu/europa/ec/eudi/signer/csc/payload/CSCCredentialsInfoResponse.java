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

import java.util.List;

/**
 * Body for response of credentials/info - information about a specific
 * credential record
 * From section 11.5 of the CSC API V_1.0.4.0 spec
 */
public class CSCCredentialsInfoResponse {

    // OPTIONAL
    // A free form description of the credential in the lang language. The maximum size of the string is 255 characters.
    private String description;

    private Key key;

    private Cert cert;

    // REQUIRED
    // One of implicit | explicit | oauth2code
    // Specifies one of the authorization modes. For more information also see  section 8.2:
    // • “implicit”: the authorization process is managed by the remote service autonomously. Authentication factors
    // are managed by the RSSP by interacting directly with the user, and not by the signature application.
    // • “explicit”: the authorization process is managed by the signature  application, which collects authentication
    // factors like PIN or One-Time Passwords (OTP).
    // • “oauth2code”: the authorization process is managed by the remote service using an OAuth 2.0 mechanism based on
    // authorization code as  described in Section 1.3.1 of RFC 6749 [11].
    private String authMode;

    // OPTIONAL
    // One of 1 | 2
    // Specifies if the RSSP will generate for this credential a signature activation data (SAD) that contains a link to the hash to-be-signed:
    // • “1”: The hash to-be-signed is not linked to the signature activation data.
    // • “2”: The hash to-be-signed is linked to the signature activation data.
    // This value is OPTIONAL and the default value is “1”.
    // NOTE: As decribed in section 8.2, one difference between SCAL1 and SCAL2, as described in CEN TS 119 241-1 [i.5],
    // is that for SCAL2, the signature activation data needs to have a link to the data to-be-signed. The value “2” only gives
    // information on the link between the hash and the SAD, it does not give information if a full SCAL2 as described
    // in CEN TS 119 241-1 [i.5] is implemented.
    private String SCAL;

    private PIN PIN;

    private OTP OTP;

    // REQUIRED
    // Must be 1 or greater 1 A number equal or higher to 1 representing the maximum number of signatures that can be
    // created with this credential with a single authorization request (e.g. by calling credentials/signHash method, as
    // defined in section 11.9, once with multiple hash values or calling it multiple times). The value of numSignatures
    // specified in the authorization request SHALL NOT exceed the value of this value.
    private long multisign;

    // OPTIONAL
    // The lang as defined in the Output parameter table in section 11.1.
    private String lang;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Key getKey() {
        return key;
    }

    public void setKey(Key key) {
        this.key = key;
    }

    public Cert getCert() {
        return cert;
    }

    public void setCert(Cert cert) {
        this.cert = cert;
    }

    public String getAuthMode() {
        return authMode;
    }

    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }

    public String getSCAL() {
        return SCAL;
    }

    public void setSCAL(String SCAL) {
        this.SCAL = SCAL;
    }

    public CSCCredentialsInfoResponse.PIN getPIN() {
        return PIN;
    }

    public void setPIN(CSCCredentialsInfoResponse.PIN PIN) {
        this.PIN = PIN;
    }

    public CSCCredentialsInfoResponse.OTP getOTP() {
        return OTP;
    }

    public void setOTP(CSCCredentialsInfoResponse.OTP OTP) {
        this.OTP = OTP;
    }

    public long getMultisign() {
        return multisign;
    }

    public void setMultisign(long multisign) {
        this.multisign = multisign;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public static class Key {

        // REQUIRED
        // One of enabled | disabled
        // The status of the signing key of the credential:
        // • “enabled”: the signing key is enabled and can be used for signing.
        // • “disabled”: the signing key is disabled and cannot be used for signing.
        // This MAY occur when the owner has disabled it or when the RSSP has detected that the associated certificate is expired or revoked.
        private String status;

        // REQUIRED
        // The list of OIDs of the supported key algorithms.
        // For example: 1.2.840.113549.1.1.1 = RSA encryption,
        // 1.2.840.10045.4.3.2 = ECDSA with SHA256.
        private List<String> algo;

        // REQUIRED
        // Number The length of the cryptographic key in bits.
        private String len;

        // REQUIRED Conditional
        // The OID of the ECDSA curve.
        // The value SHALL only be returned if keyAlgo is based on ECDSA.
        private String curve;

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public List<String> getAlgo() {
            return algo;
        }

        public void setAlgo(List<String> algo) {
            this.algo = algo;
        }

        public String getLen() {
            return len;
        }

        public void setLen(String len) {
            this.len = len;
        }

        public String getCurve() {
            return curve;
        }

        public void setCurve(String curve) {
            this.curve = curve;
        }
    }

    public static class Cert {

        // OPTIONAL
        // One of valid | expired | revoked | suspended
        // The status of validity of the end entity certificate.
        // The value is OPTIONAL, so the remote service SHOULD only return a value
        // that is accurate and consistent with the actual validity status of the
        // certificate at the time the response is generated.
        private String status;

        // REQUIRED Conditional
        // One or more Base64-encoded X.509v3 certificates from the certificate chain.
        // If the certificates parameter is “chain”, the entire certificate chain
        // SHALL be returned with the end entity certificate at the beginning of the
        // array.
        // If the certificates parameter is “single”, only the end entity certificate
        // SHALL be returned. If the certificates parameter is “none”, this value
        // SHALL NOT be returned.
        private List<String> certificates;

        // REQUIRED_Conditional
        // The Issuer Distinguished Name from the X.509v3 end entity certificate as
        // UTF-8-encoded character string according to RFC 4514 [4]. This value SHALL
        // be returned when certInfo is “true”.
        private String issuerDN;

        // REQUIRED_Conditional
        // The Serial Number from the X.509v3 end entity certificate represented as
        // hex-encoded string format.
        // This value SHALL be returned when certInfo is “true”.
        private String serialNumber;

        // REQUIRED_Conditional
        // The Subject Distinguished Name from the X.509v3 end entity certificate as
        // UTF-8-encoded character string,according to RFC 4514 [4].
        // This value SHALL be returned when certInfo is “true”.
        private String subjectDN;

        // REQUIRED_Conditional
        // The validity start date from the X.509v3 end entity certificate as character
        // string, encoded as GeneralizedTime (RFC 5280 [8]) (e.g. “YYYYMMDDHHMMSSZ”)
        // This value SHALL be returned when certInfo is “true”.
        private String validFrom;

        // REQUIRED_Conditional
        // The validity end date from the X.509v3 end enity certificate as character
        // string, encoded as GeneralizedTime (RFC 5280 [8]) (e.g. “YYYYMMDDHHMMSSZ”).
        // This value SHALL be returned when certInfo is “true”.
        private String validTo;

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public List<String> getCertificates() {
            return certificates;
        }

        public void setCertificates(List<String> certificates) {
            this.certificates = certificates;
        }

        public String getIssuerDN() {
            return issuerDN;
        }

        public void setIssuerDN(String issuerDN) {
            this.issuerDN = issuerDN;
        }

        public String getSerialNumber() {
            return serialNumber;
        }

        public void setSerialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
        }

        public String getSubjectDN() {
            return subjectDN;
        }

        public void setSubjectDN(String subjectDN) {
            this.subjectDN = subjectDN;
        }

        public String getValidFrom() {
            return validFrom;
        }

        public void setValidFrom(String validFrom) {
            this.validFrom = validFrom;
        }

        public String getValidTo() {
            return validTo;
        }

        public void setValidTo(String validTo) {
            this.validTo = validTo;
        }
    }

    public static class PIN {

        // REQUIRED_Conditional
        // One of true | false | optional Specifies if a text-based PIN is required,
        // forbidden, or optional. This value SHALL be present only when authMode is
        // “explicit”.
        private String presence;

        // REQUIRED_Conditional
        // One of A | N The data format of the PIN string: • “A”: the PIN string
        // contains alphanumeric text and/or symbols like “-.%!$@#+”. • “N”: the PIN
        // string only contains numeric text. This value SHALL be present only when
        // authMode is “explicit” and PIN/presence is not “false”. NOTE: The size of the
        // expected PIN is not specified, since this information could help an attacker
        // in performing guessing attacks.
        private String format;

        // OPTIONAL_Conditional
        // A label for the data field used to collect the PIN in the user interface of
        // the signature application, in the language specified in the lang parameter.
        // This valuer MAY be present only when authMode is “explicit” and PIN/presence
        // is not “false”. The maximum size of the string is 255 characters.
        private String label;

        // OPTIONAL_Conditional
        // A free form description of the PIN in the language specified in the lang
        // parameter. This value MAY be present only when authMode is “explicit” and
        // PIN/presence is not “false”. The maximum size of the string is 255
        // characters.
        private String description;

        public String getPresence() {
            return presence;
        }

        public void setPresence(String presence) {
            this.presence = presence;
        }

        public String getFormat() {
            return format;
        }

        public void setFormat(String format) {
            this.format = format;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }
    }

    public static class OTP {

        // REQUIRED_Conditional
        // One oftrue | false | optional Specifies if a text-based One-Time Password
        // (OTP) is required, forbidden, or optional. This value SHALL be present only
        // when authMode is “explicit”.
        private String presence;

        // REQUIRED_Conditional
        // One of offline | online The type of the OTP: • “offline”: The OTP is
        // generated offline by a dedicated device and does not require the client to
        // invoke the credentials/sendOTP method. • “online”: The OTP is generated
        // online by the remote service when the client invokes the credentials/sendOTP
        // method. This value SHALL be present only when authMode is “explicit” and
        // OTP/presence is not “false”.
        private String type;

        // REQUIRED_Conditional
        // One of A | N The data format of the OTP string: • “A”: the OTP string
        // contains alphanumeric text and/or symbols like “-.%!$@#+”. • “N”: the OTP
        // string only contains numeric text. This value SHALL be present only when
        // authMode is “explicit” and OTP/presence is not “false”.
        private String format;

        // OPTIONAL_Conditional
        // A label for the data field used to collect the OTP in the user interface of
        // the signature application, in the language specified in the lang parameter.
        // This value MAY be present only when authMode is “explicit” and OTP/presence
        // is not “false”. The maximum size of the string is 255 characters.
        private String label;

        // OPTIONAL_Conditional
        // A free form description of the OTP mechanism in the language specified in the
        // lang parameter. This value MAY be present only when authMode is “explicit”
        // and OTP/presence is not “false”. The maximum size of the string is 255
        // characters.
        private String description;

        // REQUIRED_Conditional
        // The identifier of the OTP device or application. This value SHALL be present
        // only when authMode is “explicit” and OTP/presence is not “false”.
        private String ID;

        // OPTIONAL_Conditional
        // The provider of the OTP device or application. This value MAY be present only
        // when authMode is “explicit” and OTP/presence is not “false”.
        private String provider;

        public String getPresence() {
            return presence;
        }

        public void setPresence(String presence) {
            this.presence = presence;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getFormat() {
            return format;
        }

        public void setFormat(String format) {
            this.format = format;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getID() {
            return ID;
        }

        public void setID(String ID) {
            this.ID = ID;
        }

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }
    }
}
