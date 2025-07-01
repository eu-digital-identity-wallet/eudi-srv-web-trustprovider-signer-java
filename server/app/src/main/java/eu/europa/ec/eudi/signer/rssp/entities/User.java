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

package eu.europa.ec.eudi.signer.rssp.entities;

import jakarta.persistence.*;
import javax.validation.constraints.NotNull;

import eu.europa.ec.eudi.signer.rssp.api.model.DateAudit;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

@Entity
@Table(name = "users", uniqueConstraints = @UniqueConstraint(columnNames = { "hash" }))
public class User extends DateAudit {
    @Id
    private String id;

    @NotNull
    private String role;

    @NotNull
    private String hash;

    @NotNull
    @Column(name = "issuing_country")
    private String issuingCountry;

    @Column(name = "issuance_authority")
    private String issuanceAuthority;

    public String determineHash(String familyName, String givenName, String birthDate, String country)
            throws NoSuchAlgorithmException {
        String familyNameAndGivenNameAndBirthDateAndCountry = familyName + ";" + givenName + ";" + birthDate + ";"
                + country;
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(familyNameAndGivenNameAndBirthDateAndCountry.getBytes());
        return Base64.getEncoder().encodeToString(result);
    }

    public User() {
        this.id = UUID.randomUUID().toString();
    }

    public User(String familyName, String givenName, String birthDate, String issuingCountry, String issuanceAuthority,
            String role) throws NoSuchAlgorithmException {
        this.id = UUID.randomUUID().toString();
        this.role = role;
        this.hash = determineHash(familyName, givenName, birthDate, issuingCountry);
        this.issuingCountry = issuingCountry;
        this.issuanceAuthority = issuanceAuthority;
    }

    public User(String id) {
        this.id = id;
    }

    public String getId() {
        return this.id;
    }

    public String getHash() {
        return this.hash;
    }

    public String getRole() {
        return this.role;
    }

    public String getIssuingCountry() {
        return issuingCountry;
    }

    public String getIssuanceAuthority() {
        return issuanceAuthority;
    }

    @Override
    public String toString() {
        String sb = "UserOID4VP{" +
                "id='" + id + '\'' +
                ", hash='" + hash + '\'' +
                ", role='" + role + '\'' +
                ", issuingCountry='" + issuingCountry + '\'' +
                ", issuanceAuthority='" + issuanceAuthority + '\'' +
                '}';
        return sb;
    }
}
