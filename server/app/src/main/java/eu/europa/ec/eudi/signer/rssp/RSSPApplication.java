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

import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.rssp.common.config.*;
import eu.europa.ec.eudi.signer.rssp.common.config.JwtConfigProperties;
import eu.europa.ec.eudi.signer.rssp.crypto.certificates.LocalCertificateIssuer;
import eu.europa.ec.eudi.signer.rssp.crypto.certificates.EjbcaCertificateIssuer;
import eu.europa.ec.eudi.signer.rssp.crypto.certificates.ICertificateIssuer;
import eu.europa.ec.eudi.signer.rssp.crypto.keys.EncryptionHelper;
import eu.europa.ec.eudi.signer.rssp.crypto.keys.HsmKeysService;
import eu.europa.ec.eudi.signer.rssp.crypto.keys.IKeysService;
import eu.europa.ec.eudi.signer.rssp.crypto.keys.LocalKeysService;
import eu.europa.ec.eudi.signer.rssp.ejbca.EJBCAService;
import eu.europa.ec.eudi.signer.rssp.hsm.HSMService;
import eu.europa.ec.eudi.signer.rssp.repository.ConfigRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.ApplicationPidFileWriter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableConfigurationProperties({ JwtConfigProperties.class, CSCProperties.class, VerifierProperties.class, CertificatesProperties.class, TrustedIssuersCertificatesProperties.class, AuthProperties.class, SADProperties.class, KeysProperties.class })
public class RSSPApplication {
    private static final Logger logger = LoggerFactory.getLogger(RSSPApplication.class);

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

    @Bean
    public IKeysService setKeysService(@Autowired KeysProperties keysProperties, @Autowired AuthProperties authProperties, @Autowired ConfigRepository configRep, @Autowired LoggerUtil loggerUtil) throws Exception {
		logger.info("Use HSM? {}", keysProperties.useHsm());

        EncryptionHelper encryptionHelper = new EncryptionHelper(authProperties);

        if(keysProperties.useHsm()){
            HSMService hsmService = new HSMService();
            IKeysService keysService = new HsmKeysService(hsmService, keysProperties, encryptionHelper, configRep);
            logger.info("Set up Keys Service that uses HSM.");
            return keysService;
        }
        else{
            IKeysService keysService = new LocalKeysService(keysProperties, encryptionHelper, configRep);
            logger.info("Set up Keys Service that doesn't use HSM.");
            return keysService;
        }
    }

    @Bean
    public ICertificateIssuer setCertificateService(@Autowired CertificatesProperties certificatesProperties) throws Exception {
        logger.info("Use EJBCA? {}", certificatesProperties.useEjbca());
        if(certificatesProperties.useEjbca()){
            EJBCAService ejbcaServiceService = new EJBCAService(certificatesProperties.getEjbca());
            ICertificateIssuer certificatesService = new EjbcaCertificateIssuer(ejbcaServiceService);
            logger.info("Set up Certificate Service that uses EJBCA.");
			return certificatesService;
        }
        else {
            ICertificateIssuer certificatesService = new LocalCertificateIssuer(certificatesProperties.getCaSubject());
            logger.info("Set up Certificate Service that doesn't use EJBCA.");
			return certificatesService;
        }
    }
}