package eu.europa.ec.eudi.signer.rssp.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;

@PropertySource("file:application.yml")
@ConfigurationProperties(prefix = "oid4vp")
public class OID4VPConfig {
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
