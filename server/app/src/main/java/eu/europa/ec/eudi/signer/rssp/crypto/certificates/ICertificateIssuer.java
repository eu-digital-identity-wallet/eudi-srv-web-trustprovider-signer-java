package eu.europa.ec.eudi.signer.rssp.crypto.certificates;

public interface ICertificateIssuer {
	CertificatesDTO issueCertificate(String certificateSigningRequest, String countryCode, String givenName, String surname, String subjectCN) throws Exception;
}
