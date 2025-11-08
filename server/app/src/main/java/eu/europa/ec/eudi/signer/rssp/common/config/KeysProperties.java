package eu.europa.ec.eudi.signer.rssp.common.config;

import jakarta.validation.constraints.Pattern;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

@ConfigurationProperties(prefix = "keys")
public class KeysProperties {
	private boolean useHsm;
	// properties for controlling crypto algos, signing, etc
	@Pattern(regexp = "^(RSA)$", message = "Not yet added support for non-RSA algorithms")
	private String keyAlgorithm;
	private int keySize;
	private String signatureAlgorithm;

	public boolean useHsm() {
		return useHsm;
	}

	public void setUseHsm(boolean useHsm) {
		this.useHsm = useHsm;
	}

	/**
	 * Key generation algorithm name
	 * Example: "RSA"
	 */
	public String getKeyAlgorithm() {
		return keyAlgorithm;
	}

	public void setKeyAlgorithm(String keyAlgorithm) {
		this.keyAlgorithm = keyAlgorithm;
	}

	/**
	 * Key size in bits
	 * Example: 2048
	 */
	public int getKeySize() {
		return keySize;
	}

	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}

	/**
	 * Certificate Signature algorithm name: must correspond with the key algorithm
	 * Example "SHA256WithRSA" (corresponds with "RSA")
	 */
	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public List<String> getKeyAlgorithmsOIDs(){
		if (getSignatureAlgorithm() == null || !getSignatureAlgorithm().toLowerCase().endsWith("withrsa")) {
			throw new IllegalArgumentException("TrustProviderSigner Configuration Error: signatureAlgorithm is incompatible with keyAlgorithm");
		}
		final ASN1ObjectIdentifier rsaIdentifier = PKCSObjectIdentifiers.rsaEncryption;
		String rsaOID = rsaIdentifier.toString();
		return Collections.singletonList(rsaOID);
	}

}
