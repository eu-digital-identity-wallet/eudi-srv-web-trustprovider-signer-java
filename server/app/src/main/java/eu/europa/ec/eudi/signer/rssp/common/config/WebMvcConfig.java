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

package eu.europa.ec.eudi.signer.rssp.common.config;

import eu.europa.ec.eudi.signer.common.SignerConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.HandlerTypePredicate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    public Environment env;

        public WebMvcConfig(@Autowired Environment env){
            this.env = env;
        }

        @Override
        public void addCorsMappings(CorsRegistry registry) {
            long MAX_AGE_SECS = 18000;
            String clientUrl = env.getProperty("ASSINA_CLIENT_BASE_URL");
            registry.addMapping("/**")
                    .allowedOrigins(clientUrl, "http://localhost:3000", "https://trustprovider.signer.eudiw.dev")
                    .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                    .allowedHeaders("*")
                    .allowCredentials(true)
                    .maxAge(MAX_AGE_SECS);
        }

        @Override
        public void configurePathMatch(PathMatchConfigurer configurer) {
            configurer.addPathPrefix(SignerConstants.API_URL_ROOT,
                    HandlerTypePredicate.forAnnotation(RestController.class)
                            .and(HandlerTypePredicate.forBasePackage(
                                    "eu.europa.ec.eudi.signer.rssp.api")));
            configurer.addPathPrefix(SignerConstants.CSC_URL_ROOT,
                    HandlerTypePredicate.forAnnotation(RestController.class)
                            .and(HandlerTypePredicate.forBasePackage(
                                    "eu.europa.ec.eudi.signer.rssp.csc")));
        }
}
