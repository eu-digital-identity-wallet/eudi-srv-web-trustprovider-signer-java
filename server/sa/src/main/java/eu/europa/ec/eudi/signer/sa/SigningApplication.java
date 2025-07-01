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

package eu.europa.ec.eudi.signer.sa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.ApplicationPidFileWriter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import eu.europa.ec.eudi.signer.sa.config.FileStorageConfig;
import eu.europa.ec.eudi.signer.sa.config.RSSPClientConfig;

/** Main Spring Boot application class for Trust Provider Signer application */
@EnableConfigurationProperties({ FileStorageConfig.class, RSSPClientConfig.class })
@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
public class SigningApplication {

	public static void main(String[] args) {
		SpringApplication application = new SpringApplication(SigningApplication.class);
		application.addListeners(new ApplicationPidFileWriter("./sa.pid"));
		application.run(args);
	}
}
