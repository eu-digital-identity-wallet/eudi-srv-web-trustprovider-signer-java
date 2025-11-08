package eu.europa.ec.eudi.signer.rssp.crypto.certificates;

import java.security.cert.X509Certificate;
import java.util.List;

public record CertificatesDTO(X509Certificate signingCertificate, List<X509Certificate> certificateChain) {
}
