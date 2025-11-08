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

package eu.europa.ec.eudi.signer.rssp.crypto.certificates;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.security.PublicKey;
import java.security.Security;
import java.util.*;

public class CertificateSigningRequestGenerator {
	private static final Logger log = LoggerFactory.getLogger(CertificateSigningRequestGenerator.class);

	/*Generates the information of a certificate signing request (without the signature of the private key)*/
	public byte[] generateCertificateRequestInfo(PublicKey publicKey, String givenName, String surname, String commonName, String countryName) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		SubjectPublicKeyInfo pki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

		final X500Name subjectDN = new X500NameBuilder(BCStyle.INSTANCE)
				.addRDN(BCStyle.CN, commonName)
				.addRDN(BCStyle.SURNAME, surname)
				.addRDN(BCStyle.GIVENNAME, givenName)
				.addRDN(BCStyle.C, countryName)
				.build();

		CertificationRequestInfo cri = new CertificationRequestInfo(subjectDN, pki, new DERSet());
		return cri.getEncoded();
	}

	/*Generates a certificate signing request by adding its signature*/
	public String generateCertificateRequest(byte[] certificateRequestInfo, byte[] signature) throws IOException {
		CertificationRequestInfo cri = CertificationRequestInfo.getInstance(certificateRequestInfo);
		DERBitString sig = new DERBitString(signature);
		AlgorithmIdentifier rsaWithSha256 = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
		CertificationRequest cr = new CertificationRequest(cri, rsaWithSha256, sig);
		PKCS10CertificationRequest certificateRequest = new PKCS10CertificationRequest(cr);
		return "-----BEGIN CERTIFICATE REQUEST-----\n" +  new String(Base64.getEncoder().encode(certificateRequest.getEncoded())) + "\n-----END CERTIFICATE REQUEST-----";
	}

}
