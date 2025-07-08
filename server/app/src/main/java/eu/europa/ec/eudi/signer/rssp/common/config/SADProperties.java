package eu.europa.ec.eudi.signer.rssp.common.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sad")
public class SADProperties extends TokenCommonConfig {
	@Value("${auth.sadTokenSecret}")
	private String secret;

	@Override
	public String getSecret() {
		return secret;
	}

	@Override
	public void setSecret(String secret) {
		this.secret = secret;
	}
}
