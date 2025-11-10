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

package eu.europa.ec.eudi.signer.rssp.util;

import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

public class CertificateUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Formats a date as a string according to x509 RFC 5280
     * Assumes the given date is UTC
     * 
     * @return null if the date is null otherwise formatted as YYYMMMDDHHMMSSZ
     */
    public static String x509Date(Date date) {
        if (date == null)
            return null;

        SimpleDateFormat X509DateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        return X509DateFormat.format(date);
    }

    public static String certificateToString(X509Certificate certificate) throws IOException {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(certificate);
            pemWriter.flush();
            return sw.toString();
        }
    }

    public static X509Certificate stringToCertificate(String certificateString) throws ApiException {
        try (StringReader stringReader = new StringReader(certificateString);
             PEMParser pemParser = new PEMParser(stringReader)) {
            Object object = pemParser.readObject();
            return new JcaX509CertificateConverter()
                  .getCertificate((X509CertificateHolder) object);
        }
        catch (IOException | CertificateException e){
            throw new ApiException(SignerError.FailedUnmarshallingPEM, e);
        }
    }
}
