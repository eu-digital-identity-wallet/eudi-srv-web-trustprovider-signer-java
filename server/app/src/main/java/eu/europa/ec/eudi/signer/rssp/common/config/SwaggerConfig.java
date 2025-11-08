package eu.europa.ec.eudi.signer.rssp.common.config;

import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

	@Bean
	GroupedOpenApi publicApi(){
		return GroupedOpenApi.builder()
			  .group("public-apis")
			  .pathsToMatch("/**")
			  .build();
	}
}
