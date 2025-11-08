package eu.europa.ec.eudi.signer.rssp.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sad")
public class SADProperties extends TokenCommonConfig {}
