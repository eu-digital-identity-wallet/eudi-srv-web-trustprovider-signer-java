package eu.europa.ec.eudi.signer.rssp.crypto.certificates;

import eu.europa.ec.eudi.signer.rssp.ejbca.EJBCAService;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.List;

public class EjbcaCertificateIssuer implements ICertificateIssuer {

	private final EJBCAService ejbcaService;

	public EjbcaCertificateIssuer(EJBCAService ejbcaService) {
		this.ejbcaService = ejbcaService;
	}

	public CertificatesDTO issueCertificate(String certificateString, String countryCode, String givenName, String surname, String subjectCN) throws Exception {
		List<X509Certificate> certificateAndChain = this.ejbcaService.certificateRequest(certificateString, countryCode);

		if(!validateCertificateFromCA(certificateAndChain, givenName, surname, subjectCN, countryCode)){
			throw new Exception("Certificates received from CA are not valid");
		}

		return new CertificatesDTO(certificateAndChain.get(0), certificateAndChain.subList(1, certificateAndChain.size()));
	}

	public boolean validateCertificateFromCA(List<X509Certificate> certificatesAndCertificateChain, String givenName, String surname, String subjectCN, String countryCode){
		if(certificatesAndCertificateChain.isEmpty()){
			return false;
		}

		String expectedIssuerSubjectCN = this.ejbcaService.getCertificateAuthorityNameByCountry(countryCode);

		X509Certificate certificate = certificatesAndCertificateChain.get(0);
		X500Principal subjectX500Principal = certificate.getSubjectX500Principal();
		X500Name x500SubjectName = new X500Name(subjectX500Principal.getName());
		X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
		X500Name x500IssuerName = new X500Name(issuerX500Principal.getName());

		RDN[] rdnGivenName = x500SubjectName.getRDNs(BCStyle.GIVENNAME);
		if(rdnListContainsValue(rdnGivenName, givenName)){
			return false;
		}

		RDN[] rdnSurname = x500SubjectName.getRDNs(BCStyle.SURNAME);
		if(rdnListContainsValue(rdnSurname, surname)){
			return false;
		}

		RDN[] rdnSubjectCN = x500SubjectName.getRDNs(BCStyle.CN);
		if(rdnListContainsValue(rdnSubjectCN, subjectCN)){
			return false;
		}

		RDN[] rdnCountry = x500SubjectName.getRDNs(BCStyle.C);
		if(rdnListContainsValue(rdnCountry, countryCode)){
			return false;
		}


		// System.out.println(expectedIssuerSubjectCN);
		RDN[] rdnIssuerSubjectCN = x500IssuerName.getRDNs(BCStyle.CN);
		return !rdnListContainsValue(rdnIssuerSubjectCN, expectedIssuerSubjectCN);
	}

	// Verifies if the rdnListFromCertificate doesn't have the value
	// if the value is not present, returns true
	public static boolean rdnListContainsValue(RDN[] rdnListFromCertificate, String value){
		if(rdnListFromCertificate == null)
			return true;

		for (RDN rdn : rdnListFromCertificate) {
			String name = IETFUtils.valueToString(rdn.getFirst().getValue());
			if(name.equals(value))
				return false;
		}

		return true;
	}
}
