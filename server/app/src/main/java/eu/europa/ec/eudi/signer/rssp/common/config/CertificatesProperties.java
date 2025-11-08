package eu.europa.ec.eudi.signer.rssp.common.config;

import eu.europa.ec.eudi.signer.rssp.ejbca.EJBCAProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "certificates")
public class CertificatesProperties {
	private boolean useEjbca;
	private CASubject caSubject;
	private EJBCAProperties Ejbca;

	public static class CASubject{
		private String certificateFile;
		private String keyFile;
		private String commonName;
		private String organization;
		private String country;

		public String getCertificateFile() {
			return certificateFile;
		}

		public void setCertificateFile(String certificateFile) {
			this.certificateFile = certificateFile;
		}

		public String getKeyFile() {
			return keyFile;
		}

		public void setKeyFile(String keyFile) {
			this.keyFile = keyFile;
		}

		public String getCommonName() {
			return commonName;
		}

		public void setCommonName(String commonName) {
			this.commonName = commonName;
		}

		public String getOrganization() {
			return organization;
		}

		public void setOrganization(String organization) {
			this.organization = organization;
		}

		public String getCountry() {
			return country;
		}

		public void setCountry(String country) {
			this.country = country;
		}
	}

	public boolean useEjbca() {
		return useEjbca;
	}

	public void setUseEjbca(boolean useEjbca) {
		this.useEjbca = useEjbca;
	}

	public CASubject getCaSubject() {
		return caSubject;
	}

	public void setCaSubject(CASubject caSubject) {
		this.caSubject = caSubject;
	}

	public EJBCAProperties getEjbca() {
		return Ejbca;
	}

	public void setEjbca(EJBCAProperties ejbca) {
		Ejbca = ejbca;
	}
}
