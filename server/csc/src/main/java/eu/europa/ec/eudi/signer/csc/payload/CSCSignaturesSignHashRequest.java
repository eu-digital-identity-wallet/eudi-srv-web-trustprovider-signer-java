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

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

/**
 * Body for request of signatures/signHash for signing document hashes
 * From section 11.9 of the CSC API V_1.0.4.0 spec
 */
public class CSCSignaturesSignHashRequest {

    // REQUIRED
    // The credentialID as defined in the Input parameter table in section 11.5.
    @NotBlank(message = "MissingCredentialId")
    private String credentialID;

    // REQUIRED
    // The Signature Activation Data returned by the Credential Authorization
    // methods.
    @NotBlank(message = "MissingSAD")
    @JsonProperty("SAD") // must be uppercase
    private String SAD;

    // REQUIRED
    // One or more hash values to be signed.
    // This parameter SHALL contain the Base64-encoded raw message digest(s).
    @NotEmpty(message = "InvalidHashArray")
    private List<String> hash;

    // REQUIRED_Conditional
    // The OID of the algorithm used to calculate the hash value(s).
    // This parameter SHALL be omitted or ignored if the hash algorithm is
    // implicitly specified
    // by the signAlgo algorithm.
    // Only hashing algorithms as strong or stronger than SHA256 SHALL be used.
    // The hash algorithm SHOULD follow the recommendations of ETSI TS 119 312 [21].
    // ASSINA: NOT REQUIRED: implied by the signAlgo algorithm
    private String hashAlgo;

    // REQUIRED
    // The OID of the algorithm to use for signing.
    // It SHALL be one of the values allowed by the credential as returned in
    // keyAlgo by the
    // credentials/info method, as defined in section 11.5.
    @NotBlank(message = "MissingSignAlgo")
    private String signAlgo;

    // REQUIRED_Conditional
    // The Base64-encoded DER-encoded ASN.1 signature parameters, if required by the
    // signature
    // algorithm. Some algorithms like RSASSA-PSS, as defined in RFC 8917 [18],
    // may require additional parameters.
    private String signAlgoParams;

    // OPTIONAL
    // The clientData as defined in the Input parameter table in section 8.3.2.
    private String clientData;

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public String getSAD() {
        return SAD;
    }

    public void setSAD(String SAD) {
        this.SAD = SAD;
    }

    public List<String> getHash() {
        return hash;
    }

    public void setHash(List<String> hash) {
        this.hash = hash;
    }

    public String getHashAlgo() {
        return hashAlgo;
    }

    public void setHashAlgo(String hashAlgo) {
        this.hashAlgo = hashAlgo;
    }

    public String getSignAlgo() {
        return signAlgo;
    }

    public void setSignAlgo(String signAlgo) {
        this.signAlgo = signAlgo;
    }

    public String getSignAlgoParams() {
        return signAlgoParams;
    }

    public void setSignAlgoParams(String signAlgoParams) {
        this.signAlgoParams = signAlgoParams;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }
}
