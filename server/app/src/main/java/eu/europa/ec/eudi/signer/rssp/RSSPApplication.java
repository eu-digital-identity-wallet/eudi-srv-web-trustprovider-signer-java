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

package eu.europa.ec.eudi.signer.rssp;

import eu.europa.ec.eudi.signer.rssp.common.config.*;
import eu.europa.ec.eudi.signer.rssp.common.config.JwtConfigProperties;
import eu.europa.ec.eudi.signer.rssp.ejbca.EJBCAProperties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.ApplicationPidFileWriter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({ JwtConfigProperties.class, CSCProperties.class, VerifierProperties.class, EJBCAProperties.class, TrustedIssuersCertificatesProperties.class, AuthProperties.class, SADProperties.class })
public class RSSPApplication {
    private static final Logger logger = LogManager.getLogger(RSSPApplication.class);

    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(RSSPApplication.class);
        application.addListeners(new ApplicationPidFileWriter("./rssp.pid"));

        try {
            application.run(args);
        } catch (Exception e) {
            logger.error("RSSP Application Failed to Start.");
            System.exit(1);
        }
    }
}