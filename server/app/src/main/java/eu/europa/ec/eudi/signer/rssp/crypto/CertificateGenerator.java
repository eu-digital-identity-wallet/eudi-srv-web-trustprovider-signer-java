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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.eudi.signer.rssp.common.config.CryptoConfig;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

/**
 * Generates key pairs and self-signed certificates
 */
public class CertificateGenerator {
	private List<String> keyAlgorithmOIDs;
	private final CryptoConfig config;
	private boolean initialized;
	KeyPairGenerator keyPairGenerator;

	private static final Logger log = LoggerFactory.getLogger(CertificateGenerator.class);

	public CertificateGenerator(CryptoConfig config) {
		this.config = config;
		initialized = false;
	}

	// lazy init
	private void init() {
		if (!initialized) {
			try {
				if (!"RSA".equalsIgnoreCase(config.getKeyAlgorithm())) {
					String msg = "Not YET Implemented support for non RSA algorithms";
					log.error(msg);
					throw new IllegalArgumentException(msg);
				}
				// this is not as robust as using a library but works the same way as the sun
				// library sun.security.x509.AlgorithmId.checkKeyAndSigAlgMatch

				// TODO restore the SUN code reference or find the proper BC way to get the OID
				// And to confirm that the key sig matches
				if (config.getSignatureAlgorithm() == null ||
						!config.getSignatureAlgorithm().toLowerCase().endsWith("withrsa")) {
					String error = "Assina Configuration Error: signatureAlgorithm is incompatible with keyAlgorithm";
					log.error(error);
					throw new IllegalArgumentException(error);
				}
				final ASN1ObjectIdentifier rsaIdentifier = PKCSObjectIdentifiers.rsaEncryption;
				String rsaOID = rsaIdentifier.toString();
				keyAlgorithmOIDs = Collections.singletonList(rsaOID); // TODO could there be more?

				keyPairGenerator = KeyPairGenerator.getInstance(config.getKeyAlgorithm());
				keyPairGenerator.initialize(config.getKeySize(), new SecureRandom());

				/*
				 * // NOTE: This is a SUN class - it makes this code JRE dependent it also has
				 * // compilation problems with Java 11
				 * final sun.security.x509.AlgorithmId
				 * algorithmId = sun.security.x509.AlgorithmId.get(config.getKeyAlgorithm());
				 * 
				 * // TODO could there be more keys?
				 * keyAlgorithmOIDs =
				 * Collections.singletonList(algorithmId.getOID().toString());
				 * 
				 * // throws IllegalArgument exception if the key and signature algorithms are
				 * incompatible
				 * try {
				 * sun.security.x509.AlgorithmId.checkKeyAndSigAlgMatch(config.getKeyAlgorithm()
				 * , config.getSignatureAlgorithm());
				 * } catch (IllegalArgumentException e) {
				 * log.
				 * error("Assina Configuration Error: signatureAlgorithm is incompatible with "
				 * + "keyAlgorithm", e);
				 * // re throw the exception - we cannot recover from this
				 * throw e;
				 * }
				 */
			} catch (NoSuchAlgorithmException nsae) {
				log.error("Failed to init crypto", nsae);
				throw new IllegalArgumentException(nsae);
			} finally {
				initialized = true;
			}
		}
	}

	public List<String> getKeyAlgorithmOIDs() {
		init();
		return keyAlgorithmOIDs;
	}

	public int getKeyBitLength() {
		return config.getKeySize();
	}

	public String getECSDACurveOID() {
		if (!"RSA".equalsIgnoreCase(config.getKeyAlgorithm())) {
			throw new IllegalArgumentException("Not YET Implemented support for non RSA algorithms");
		}
		return null;
	}

	public boolean isCertificateExpired(X509Certificate x509Certificate) {
		return x509Certificate.getNotAfter().before(nowUTC());
	}

	private Date nowUTC() {
		Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		return calendar.getTime();
	}

	public byte[] generateCertificateRequestInfo(BigInteger modulus, BigInteger exponent, String givenName,
			String surname, String commonName, String countryName)
			throws Exception {
		init();
		Security.addProvider(new BouncyCastleProvider());

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pKeySpec = new RSAPublicKeySpec(modulus, exponent);
		PublicKey pk = keyFactory.generatePublic(pKeySpec);
		SubjectPublicKeyInfo pki = SubjectPublicKeyInfo.getInstance(pk.getEncoded());

		final X500Name subjectDN = new X500NameBuilder(BCStyle.INSTANCE)
				.addRDN(BCStyle.CN, commonName)
				.addRDN(BCStyle.SURNAME, surname)
				.addRDN(BCStyle.GIVENNAME, givenName)
				.addRDN(BCStyle.C, countryName)
				.build();

		CertificationRequestInfo cri = new CertificationRequestInfo(subjectDN, pki, new DERSet());
		return cri.getEncoded();
	}

	public PKCS10CertificationRequest generateCertificateRequest(byte[] certificateRequestInfo, byte[] signature) {
		CertificationRequestInfo cri = CertificationRequestInfo.getInstance(certificateRequestInfo);
		DERBitString sig = new DERBitString(signature);

		AlgorithmIdentifier rsaWithSha256 = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
		CertificationRequest cr = new CertificationRequest(cri, rsaWithSha256, sig);
		return new PKCS10CertificationRequest(cr);
	}
}
