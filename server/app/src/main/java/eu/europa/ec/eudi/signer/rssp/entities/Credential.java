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


import eu.europa.ec.eudi.signer.rssp.api.model.DateAudit;
import eu.europa.ec.eudi.signer.rssp.api.model.StringListConverter;
import jakarta.persistence.*;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Represents the credential object from the CSC Spec v 1.0.4.0:
 * credential: cryptographic object and related data used to support remote
 * digital signatures over the Internet.
 * Consists of the combination of a public/private key pair (also named “signing
 * key” in CEN EN 419 241-1 [i.5])
 * and a X.509 public key certificate managed by a remote signing service
 * provider on behalf of a user.
 */
@Entity
@Table(name = "assina_credential", uniqueConstraints = @UniqueConstraint(columnNames = { "owner", "alias" }))
public class Credential extends DateAudit {
	// need to include the other details the key OIDs etc.

	@Id
	private String id;
	private String alias;
	private String owner;
	private String description;

	// REQUIRED
	// matches key status in CSC API
	// One of enabled | disabled
	// The status of the signing key of the credential:
	// • “enabled”: the signing key is enabled and can be used for signing.
	// • “disabled”: the signing key is disabled and cannot be used for signing.
	// This MAY occur when the owner has disabled it or when the RSSP has detected
	// that the associated certificate is expired or revoked.
	@Column(name = "key_enabled")
	private boolean keyEnabled = true;

	// The list of OIDs of the supported key algorithms.
	// For example: 1.2.840.113549.1.1.1 = RSA encryption,
	// 1.2.840.10045.4.3.2 = ECDSA with SHA256.
	@Convert(converter = StringListConverter.class)
	@Column(name = "key_algorithmoids", length = 2000)
	private List<String> keyAlgorithmOIDs;

	// Number The length of the cryptographic key in bits.
	@Column(name = "key_bit_length")
	private int keyBitLength;

	// The OID of the ECDSA curve.
	// The value SHALL only be returned if keyAlgo is based on ECDSA.
	@Column(name = "key_curve")
	private String keyCurve;

	// The Issuer Distinguished Name from the X.509v3 end entity certificate as
	// UTF-8-encoded character string according to RFC 4514 [4]. This value SHALL
	@Column(name = "issuerdn")
	private String issuerDN;

	// The Serial Number from the X.509v3 end entity certificate represented as
	// hex-encoded string format.
	@Column(name = "serial_number")
	private String serialNumber;

	// The Subject Distinguished Name from the X.509v3 end entity certificate as
	// UTF-8-encoded character string,according to RFC 4514 [4].
	@Column(name = "subjectdn")
	private String subjectDN;

	// The validity start date from the X.509v3 end entity certificate as character
	// string, encoded as GeneralizedTime (RFC 5280 [8]) (e.g. “YYYYMMDDHHMMSSZ”)
	@Column(name = "valid_from")
	private String validFrom;

	// The validity end date from the X.509v3 end enity certificate as character
	// string, encoded as GeneralizedTime (RFC 5280 [8]) (e.g. “YYYYMMDDHHMMSSZ”).
	@Column(name = "valid_to")
	private String validTo;

	@Column(length = 2000)
	private String certificate;

	@Column(length = 2000)
	private byte[] privateKeyHSM;

	@Column(length = 2000)
	private byte[] publicKeyHSM;

	// @ElementCollection
	@OneToMany(fetch = FetchType.LAZY, mappedBy = "credential", cascade = CascadeType.ALL)
	// @Column(name = "certificate_chain")
	private List<Certificate> certificateChain;

	public Credential() {
		id = UUID.randomUUID().toString();
	}

	public String getId() {
		return id;
	}

	public void setId(final String id) {
		this.id = id;
	}

	public String getAlias() {
		return this.alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(final String description) {
		this.description = description;
	}

	public String getOwner() {
		return owner;
	}

	public void setOwner(String owner) {
		this.owner = owner;
	}

	public String getCertificate() {
		return certificate;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}

	public List<String> getCertificateChains() {
		return this.certificateChain.stream().map(Certificate::getCertificate).collect(Collectors.toList());
	}

	public void setCertificateChains(List<Certificate> certs) {
		this.certificateChain = certs;
	}

	public boolean isKeyEnabled() {
		return keyEnabled;
	}

	public void setKeyEnabled(boolean enabled) {
		this.keyEnabled = enabled;
	}

	public List<String> getKeyAlgorithmOIDs() {
		return keyAlgorithmOIDs;
	}

	public void setKeyAlgorithmOIDs(List<String> keyAlgoritmOIDs) {
		this.keyAlgorithmOIDs = keyAlgoritmOIDs;
	}

	public int getKeyBitLength() {
		return keyBitLength;
	}

	public void setKeyBitLength(int keyBitLength) {
		this.keyBitLength = keyBitLength;
	}

	public String getECDSACurveOID() {
		return keyCurve;
	}

	public void setECDSACurveOID(String curve) {
		this.keyCurve = curve;
	}

	public void setSubjectDN(String subjectDN) {
		this.subjectDN = subjectDN;
	}

	public String getSubjectDN() {
		return this.subjectDN;
	}

	public void setIssuerDN(String issuerDN) {
		this.issuerDN = issuerDN;
	}

	public String getIssuerDN() {
		return this.issuerDN;
	}

	public void setValidFrom(String validFrom) {
		this.validFrom = validFrom;
	}

	public String getValidFrom() {
		return this.validFrom;
	}

	public void setValidTo(String validTo) {
		this.validTo = validTo;
	}

	public String getValidTo() {
		return this.validTo;
	}

	public byte[] getPrivateKeyHSM() {
		return this.privateKeyHSM;
	}

	public void setPrivateKeyHSM(byte[] privateKey) {
		this.privateKeyHSM = privateKey;
	}

	public byte[] getPublicKeyHSM() {
		return this.publicKeyHSM;
	}

	public void setPublicKeyHSM(byte[] publicKey) {
		this.publicKeyHSM = publicKey;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		Credential that = (Credential) o;
		return Objects.equals(owner, that.owner) &&
				Objects.equals(certificate, that.certificate) &&
				Arrays.equals(publicKeyHSM, that.publicKeyHSM);
	}

	@Override
	public int hashCode() {
		return Objects.hash(owner, certificate, publicKeyHSM);
	}
}
