package eu.europa.ec.eudi.signer.rssp.crypto.certificates;

import eu.europa.ec.eudi.signer.rssp.common.config.CertificatesProperties;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class LocalCertificateIssuer implements ICertificateIssuer {

	private X509Certificate certificate;
	private PrivateKey privateKey;

	public LocalCertificateIssuer(CertificatesProperties.CASubject caSubject) throws Exception {
		if(caSubject.getCertificateFile() != null && caSubject.getKeyFile() != null && Files.exists(Paths.get(caSubject.getCertificateFile())) && Files.exists(Paths.get(caSubject.getKeyFile()))){
			loadCertificateAndKey(caSubject);
		}
		else createCertificateAndKey(caSubject);
	}

	private void loadCertificateAndKey(CertificatesProperties.CASubject caSubject) throws Exception {
		try (FileInputStream certIn = new FileInputStream(caSubject.getCertificateFile());
			 FileInputStream keyIn = new FileInputStream(caSubject.getKeyFile())) {
			byte[] certificateBytes = certIn.readAllBytes();
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			this.certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBytes));

			byte[] keyBytes = keyIn.readAllBytes();
			KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // or "EC", "Ed25519", etc.
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
			this.privateKey = keyFactory.generatePrivate(keySpec);
		}
	}

	private void createCertificateAndKey(CertificatesProperties.CASubject caSubject) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGen.initialize(2048);
		KeyPair keyPair = keyPairGen.generateKeyPair();

		X500Name issuer = new X500Name("CN="+caSubject.getCommonName()+", O="+caSubject.getOrganization()+", C="+caSubject.getCountry());

		Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24);
		Date notAfter = new Date(System.currentTimeMillis() + (10L * 365 * 24 * 60 * 60 * 1000)); // 10 years

		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter,
			  issuer, keyPair.getPublic());

		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
		X509CertificateHolder holder = certBuilder.build(signer);
		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
		cert.verify(keyPair.getPublic(), "BC");

		this.certificate = cert;
		this.privateKey = keyPair.getPrivate();

		try (FileOutputStream certOut = new FileOutputStream(caSubject.getCertificateFile());
			 FileOutputStream keyOut = new FileOutputStream(caSubject.getKeyFile())) {
			certOut.write(cert.getEncoded());
			keyOut.write(keyPair.getPrivate().getEncoded());
		}
	}

	@Override
	public CertificatesDTO issueCertificate(String certificateSigningRequest, String countryCode, String givenName, String surname, String subjectCN) throws Exception {
		// generate signing certificate
		PKCS10CertificationRequest certificateRequest = fromPEM(certificateSigningRequest);
		X509Certificate certificate = generateCertificate(new JcaPKCS10CertificationRequest (certificateRequest));

		// get certificate chain
		List<X509Certificate> certificateChain = new ArrayList<>();
		certificateChain.add(this.certificate);

		return new CertificatesDTO(certificate, certificateChain);
	}

	public static PKCS10CertificationRequest fromPEM(String pemCSR) throws Exception {
		try (PEMParser pemParser = new PEMParser(new StringReader(pemCSR))) {
			Object obj = pemParser.readObject();
			if (obj instanceof PKCS10CertificationRequest) {
				return (PKCS10CertificationRequest) obj;
			} else {
				throw new IllegalArgumentException("Not a valid CSR object");
			}
		}
	}


	private X509Certificate generateCertificate(JcaPKCS10CertificationRequest certificateRequest) throws Exception{
		X500Name issuer = new X500Name(this.certificate.getSubjectX500Principal().getName());
		X500Name subject = certificateRequest.getSubject();
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

		Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24);
		Date notAfter = new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000)); // 1 year

		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
			  issuer,
			  serial,
			  notBefore,
			  notAfter,
			  subject,
			  certificateRequest.getPublicKey()
		);

		// sign the certificate request
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(this.privateKey);
		X509CertificateHolder holder = certBuilder.build(signer);
		X509Certificate signedCert = new JcaX509CertificateConverter()
			  .setProvider("BC")
			  .getCertificate(holder);

		signedCert.verify(this.certificate.getPublicKey(), "BC");

		return signedCert;
	}
}
