package eu.europa.ec.eudi.signer.rssp.common.config;

import jakarta.validation.Valid;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.validation.annotation.Validated;

@PropertySource("file:application.yml")
@ConfigurationProperties(prefix = "oid4vp")
@Validated
public class OID4VPConfig {
	@Valid
	private VerifierProperties verifier;
	private WalletConfig wallet;

	public VerifierProperties getVerifier() {
		return verifier;
	}

	public void setVerifier(VerifierProperties verifier) {
		this.verifier = verifier;
	}

	public WalletConfig getWallet() {
		return wallet;
	}

	public void setWallet(WalletConfig wallet) {
		this.wallet = wallet;
	}

	public static class WalletConfig{
		private String scheme;

		public String getScheme() {
			return scheme;
		}

		public void setScheme(String scheme) {
			this.scheme = scheme;
		}
	}
}
