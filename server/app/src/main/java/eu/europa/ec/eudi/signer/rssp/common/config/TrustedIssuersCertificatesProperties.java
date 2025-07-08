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

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import jakarta.validation.constraints.NotNull;

@ConfigurationProperties(prefix = "trusted-issuers")
public class TrustedIssuersCertificatesProperties {

    @NotNull
    private String folder;
    private final Map<String, X509Certificate> trustIssuersCertificates;

    public TrustedIssuersCertificatesProperties(String folder) throws Exception{
        this.folder = folder;
        this.trustIssuersCertificates = new HashMap<>();

        try (Stream<Path> paths = Files.walk(Paths.get(folder))) {
            paths
                    .filter(path -> Files.isRegularFile(path) && path.toString().endsWith(".pem"))
                    .forEach(path -> {
                        System.out.println("Loading the certificate in the file: " + path);

                        // Process each file here
                        try {
                            CertificateFactory factory = CertificateFactory.getInstance("x.509");
                            FileInputStream is = new FileInputStream(path.toFile().getAbsolutePath());
                            X509Certificate CACert = (X509Certificate) factory.generateCertificate(is);
                            is.close();
                            this.trustIssuersCertificates.put(CACert.getSubjectX500Principal().toString(), CACert);
                        } catch (Exception e1) {
                            throw new RuntimeException(e1);
                        }
                    });
        }
    }

    public String getFolder() {
        return this.folder;
    }

    public Map<String, X509Certificate> getTrustIssuersCertificates() {
        return this.trustIssuersCertificates;
    }
}
