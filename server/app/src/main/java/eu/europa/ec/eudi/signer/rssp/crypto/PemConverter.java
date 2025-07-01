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

package eu.europa.ec.eudi.signer.rssp.crypto;

import eu.europa.ec.eudi.signer.rssp.common.config.CSCProperties;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class PemConverter {

    public PemConverter() {
        // Make sure the BC Provider is available
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public String certificateToString(X509Certificate certificate) throws IOException {
        return objectToPEM(certificate);
    }

    private String objectToPEM(Object object) throws IOException {
        try (StringWriter sw = new StringWriter();
                JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(object);
            pemWriter.flush();
            return sw.toString();
        }
    }

    public X509Certificate stringToCertificate(String certificateString) throws IOException, CertificateException {
        try (StringReader stringReader = new StringReader(certificateString);
                PEMParser pemParser = new PEMParser(stringReader)) {
            Object object = pemParser.readObject();
            return new JcaX509CertificateConverter()
                    .getCertificate((X509CertificateHolder) object);
        }
    }
}
