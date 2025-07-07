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

package eu.europa.ec.eudi.signer.rssp.csc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import eu.europa.ec.eudi.signer.common.AccessCredentialDeniedException;
import eu.europa.ec.eudi.signer.common.FailedConnectionVerifier;
import eu.europa.ec.eudi.signer.common.TimeoutException;
import eu.europa.ec.eudi.signer.csc.error.CSCInvalidRequest;
import eu.europa.ec.eudi.signer.csc.model.CSCConstants;
import eu.europa.ec.eudi.signer.csc.model.CertificateStatus;
import eu.europa.ec.eudi.signer.csc.payload.*;
import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.rssp.api.services.CredentialService;
import eu.europa.ec.eudi.signer.rssp.api.services.UserService;
import eu.europa.ec.eudi.signer.rssp.common.PaginationHelper;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.common.error.VPTokenInvalid;
import eu.europa.ec.eudi.signer.rssp.common.error.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.rssp.entities.Credential;
import eu.europa.ec.eudi.signer.rssp.crypto.CryptoService;
import eu.europa.ec.eudi.signer.rssp.ejbca.EJBCAService;
import eu.europa.ec.eudi.signer.rssp.entities.User;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;
import eu.europa.ec.eudi.signer.rssp.security.openid4vp.OpenId4VPService;
import eu.europa.ec.eudi.signer.rssp.security.openid4vp.VerifierClient;
import eu.europa.ec.eudi.signer.rssp.util.CertificateUtils;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;

@Service
public class CSCCredentialsService {

	// Allowed values for the certificates attribute: not used in payload but
	// derived in validation
	public enum CertificatesRequest {
		none, single, chain
	}

	private final PaginationHelper paginationHelper;
	private final VerifierClient verifierClient;
	private final OpenId4VPService userOID4VPService;
	private final EJBCAService ejbcaService;
	private final CredentialService credentialService;
	private final UserService userService;
	private final CryptoService cryptoService;
	private final CSCSADProvider sadProvider;
	private final LoggerUtil loggerUtil;

	private static final Logger logger = LogManager.getLogger(CSCCredentialsService.class);

	public CSCCredentialsService(@Autowired PaginationHelper paginationHelper, @Autowired VerifierClient verifierClient,
								 @Autowired OpenId4VPService userOID4VPService, @Autowired EJBCAService ejbcaService,
								 CredentialService credentialService, UserService userService, CryptoService cryptoService,
								 CSCSADProvider sadProvider, @Autowired LoggerUtil loggerUtil) {
		this.paginationHelper = paginationHelper;
		this.verifierClient = verifierClient;
		this.userOID4VPService = userOID4VPService;
		this.ejbcaService = ejbcaService;
		this.credentialService = credentialService;
		this.userService = userService;
		this.cryptoService = cryptoService;
		this.sadProvider = sadProvider;
		this.loggerUtil = loggerUtil;
	}

	public CSCCredentialsListResponse listCredentials(CSCCredentialsListRequest listRequest) {
		Pageable pageable;
		String nextPageToken;
		try {
			pageable = paginationHelper.pageTokenToPageable(listRequest.getPageToken(), listRequest.getMaxResults());
			nextPageToken = paginationHelper.pageableToNextPageToken(pageable);
		} catch (Exception e) {
			throw new ApiException(CSCInvalidRequest.InvalidPageToken, e);
		}

		final Page<Credential> credentialsPage = credentialService.getCredentialsByOwner(listRequest.getUserId(),
				pageable);

		List<CredentialInfo> credentialAliases = new ArrayList<>();
		for (Credential ac : credentialsPage) {
			CredentialInfo ci = new CredentialInfo(ac.getAlias(), ac.getIssuerDN(), ac.getSubjectDN(),
					ac.getValidFrom(), ac.getValidTo());
			credentialAliases.add(ci);
		}

		CSCCredentialsListResponse response = new CSCCredentialsListResponse();
		response.setCredentialInfo(credentialAliases);
		// don't set the next page token if its the last page
		if (credentialsPage.isLast()) {
			nextPageToken = null;
		}
		response.setNextPageToken(nextPageToken);
		return response;
	}

	public CSCCredentialsInfoResponse getCredentialsInfoFromAlias(UserPrincipal userPrincipal,
			CSCCredentialsInfoRequest infoRequest) {

		final String credentialAlias = infoRequest.getCredentialID();
		final Credential credential = loadCredential(userPrincipal.getId(), credentialAlias);

		CSCCredentialsInfoResponse response = new CSCCredentialsInfoResponse();

		// One of implicit | explicit | oauth2code
		response.setAuthMode(CSCConstants.CSC_AUTH_MODE);
		response.setDescription(credential.getDescription());
		// this value matches that in credential/authorize
		response.setMultisign(CSCConstants.CSC_MAX_REQUEST_SIGNATURES);
		// “1”: The hash to-be-signed is not linked to the signature activation data.
		response.setSCAL(CSCConstants.CSC_SCAL);
		response.setKey(buildKeyInfo(credential));

		CSCCredentialsInfoResponse.Cert cert = new CSCCredentialsInfoResponse.Cert();
		final String pemCertificate = credential.getCertificate();
		final X509Certificate x509Certificate = cryptoService.pemToX509Certificate(pemCertificate);
		List<String> cscCertificates = new ArrayList<>();
		switch (toCertsRequest(infoRequest.getCertificates())) {
			case none:
				break;
			case single:
				// certificates are already stored as PEM strings which are Base64 encoded
				cscCertificates.add(pemCertificate);
				break;
			case chain:
				throw new IllegalArgumentException("Not Yet Implmented");
		}
		cert.setCertificates(cscCertificates);

		if (infoRequest.isCertInfo()) {
			addCertInfo(cert, x509Certificate);
		}
		response.setCert(cert);
		if (cryptoService.isCertificateExpired(x509Certificate)) {
			cert.setStatus(CertificateStatus.expired.name());
		} else {
			cert.setStatus(CertificateStatus.valid.name());
		}

		if (infoRequest.isAuthInfo()) {
			response.setPIN(buildPINInfo());
			response.setOTP(buildOTPInfo());
		}

		return response;
	}

	/** helper to convert the string certificates property to an enum */
	private CertificatesRequest toCertsRequest(String certificates) {
		if (StringUtils.hasText(certificates)) {
			try {
				return CertificatesRequest.valueOf(certificates);
			} catch (IllegalArgumentException e) {
				// certificates was not one of none, single or chain, which is an error
				throw new ApiException(CSCInvalidRequest.InvalidCertificatesParameter);
			}
		} else {
			// certificates is optional and defaults to single
			return CertificatesRequest.single;
		}
	}

	/**
	 * Update info about the cert in the response
	 * According to the CSC standard, these properties are only set when the
	 * certInfo property
	 * is true in the request
	 */
	private void addCertInfo(CSCCredentialsInfoResponse.Cert cert, X509Certificate x509Certificate) {
		cert.setIssuerDN(x509Certificate.getIssuerDN().getName());
		cert.setSubjectDN(x509Certificate.getSubjectDN().getName());
		cert.setSerialNumber(String.valueOf(x509Certificate.getSerialNumber()));

		// per CSC spec: encoded as GeneralizedTime (RFC 5280 [8]) e.g.
		// “YYYYMMDDHHMMSSZ”
		cert.setValidFrom(CertificateUtils.x509Date(x509Certificate.getNotBefore()));
		cert.setValidTo(CertificateUtils.x509Date(x509Certificate.getNotAfter()));

	}

	private CSCCredentialsInfoResponse.OTP buildOTPInfo() {
		return null; // later we might add OTP support
	}

	private CSCCredentialsInfoResponse.PIN buildPINInfo() {
		CSCCredentialsInfoResponse.PIN pinInfo = new CSCCredentialsInfoResponse.PIN();

		// presence is true|false|optional
		// ASSINA: we are using PIN so true
		pinInfo.setPresence(Boolean.TRUE.toString());
		// PIN is numeric (use "A" for alpha, "N" for numeric only)
		pinInfo.setLabel("PIN");
		pinInfo.setDescription("PIN required for authorizing TrustProviderSigner to sign with this credential");
		pinInfo.setFormat("N");
		return pinInfo;
	}

	private CSCCredentialsInfoResponse.Key buildKeyInfo(Credential credential) {
		CSCCredentialsInfoResponse.Key key = new CSCCredentialsInfoResponse.Key();
		key.setAlgo(credential.getKeyAlgorithmOIDs());
		key.setCurve(credential.getECDSACurveOID());
		key.setLen(String.valueOf(credential.getKeyBitLength())); // num bits in key
		key.setStatus(credential.isKeyEnabled() ? "enabled" : "disabled");
		return key;
	}

	protected Credential loadCredential(String owner, String credentialAlias) {
		return credentialService.getCredentialWithAlias(owner, credentialAlias)
				.orElseThrow(
						() -> new ApiException(CSCInvalidRequest.InvalidCredentialId,
								"No credential found with the given Id", credentialAlias));
	}

	/**
	 * Valdiate the PIN provioded and generate a SAD token for the user to authorize
	 * the credentials.
	 *
	 * @param userPrincipal    user making the request - must own the credentials
	 * @param authorizeRequest authorization request
	 */
	public CSCCredentialsAuthorizeResponse authorizeCredential(UserPrincipal userPrincipal, CSCCredentialsAuthorizeRequest authorizeRequest)
			throws FailedConnectionVerifier, TimeoutException, AccessCredentialDeniedException,
			VerifiablePresentationVerificationException, VPTokenInvalid, ApiException {

		String id = userPrincipal.getId();

		Optional<User> user = userService.getUserById(id);
		if (user.isEmpty()) {
			String logMessage = SignerError.UserNotFound.getCode() + ": User not found.";
			logger.error(logMessage);
			throw new ApiException(SignerError.UserNotFound, "User " + id + " not found.");
		}

		CSCCredentialsAuthorizeResponse response = new CSCCredentialsAuthorizeResponse();
		response = authorizeCredentialWithOID4VP(user.get(), authorizeRequest, response);
		return response;
	}

	public CSCCredentialsAuthorizeResponse authorizeCredentialWithOID4VP(User user, CSCCredentialsAuthorizeRequest authorizeRequest, CSCCredentialsAuthorizeResponse response)
			throws FailedConnectionVerifier, TimeoutException, ApiException, AccessCredentialDeniedException, VerifiablePresentationVerificationException, VPTokenInvalid {
		final String credentialID = authorizeRequest.getCredentialID();
		User loaded = null;

		try {
			String message;
			System.out.println(authorizeRequest.getCode());
			if(authorizeRequest.getCode() != null)
				message = verifierClient.getVPTokenFromVerifier(user.getId(), VerifierClient.Authorization, authorizeRequest.getCode());
			else
				message = verifierClient.getVPTokenFromVerifierRecursive(user.getId(), VerifierClient.Authorization);
			Map<Integer, String> logsMap = new HashMap<>();
			loaded = this.userOID4VPService.loadUserFromVerifierResponse(message, this.ejbcaService, logsMap);
			for (Entry<Integer, String> l : logsMap.entrySet())
				loggerUtil.logsUser(1, user.getId(), l.getKey(), l.getValue());

		} catch (FailedConnectionVerifier e) {
			String logMessage = SignerError.FailedConnectionToVerifier.getCode() + ": "
					+ SignerError.FailedConnectionToVerifier.getDescription();
			logger.error(logMessage);
			loggerUtil.logsUser(0, user.getId(), 6, "");
			throw e;

		} catch (TimeoutException e) {
			String logMessage = SignerError.ConnectionVerifierTimedOut.getCode()
					+ "(authorizeCredentialWithOID4VP in CSCCredentialsService.class): "
					+ SignerError.ConnectionVerifierTimedOut.getDescription();
			logger.error(logMessage);
			loggerUtil.logsUser(0, user.getId(), 6, "");
			throw e;

		} catch (VerifiablePresentationVerificationException e) {
			if (e.getType() == VerifiablePresentationVerificationException.Integrity) {
				loggerUtil.logsUser(0, user.getId(), 9, "");
			} else if (e.getType() == VerifiablePresentationVerificationException.Signature) {
				loggerUtil.logsUser(0, user.getId(), 8, "");
			}
			loggerUtil.logsUser(0, user.getId(), 6,
					e.getError().getFormattedMessage());
			String logMessage = e.getError().getCode()
					+ "(authorizeCredentialWithOID4VP in CSCCredentialsService.class) " + e.getError().getDescription()
					+ ": " + e.getMessage();
			logger.error(logMessage);
			throw e;
		} catch (VPTokenInvalid e) { // there were already added the logs
			loggerUtil.logsUser(0, user.getId(), 6,
					e.getError().getFormattedMessage());
			throw e;
		} catch (ApiException e) { // there were already added the logs
			loggerUtil.logsUser(0, user.getId(), 6, "");
			throw e;
		} catch (Exception e) {
			String logMessage = SignerError.UnexpectedError.getCode()
					+ " (authorizeCredentialWithOID4VP in CSCCredentialsService.class): It was not possible to load the data from the VP Token in the authorization process: " + e.getMessage();
			logger.error(logMessage);
			loggerUtil.logsUser(0, user.getId(), 6, "");
			throw new ApiException(SignerError.SigningNotAuthorized,
					"The access to the credentials was not authorized.");
		}

		if (loaded == null) {
			String logMessage = SignerError.UnexpectedError.getCode()
					+ " (authorizeCredentialWithOID4VP in CSCCredentialsService.class) It was not possible to load the data from the VP Token in the authorization process.";
			logger.error(logMessage);
			loggerUtil.logsUser(0, user.getId(), 6, "");
			throw new ApiException(SignerError.SigningNotAuthorized,
					"The access to the credentials was not authorized.");
		}

		if (!Objects.equals(loaded.getHash(), user.getHash())) {
			String logMessage = SignerError.AccessCredentialDenied.getCode()
					+ " (authorizeCredentialWithOID4VP in CSCCredentialsService.class) The VP Token received does not have the required data to authorize the signing operation and the authorization was denied.";
			logger.error(logMessage);
			loggerUtil.logsUser(0, user.getId(), 6, "");
			throw new AccessCredentialDeniedException();
		}

		LoggerUtil.desc = "PID Hash: " + loaded.getHash();

		String SAD = sadProvider.createSAD(credentialID);
		response.setSAD(SAD);
		final long lifetimeSeconds = sadProvider.getLifetimeSeconds();
		response.setExpiresIn(lifetimeSeconds - 1); // subtract a second to be sure
		return response;
	}

	/**
	 * Function that allows to obtain a deep link to redirect the user to the wallet
	 * after the presentation request.
	 * 
	 * @param userPrincipal the user that made the request
	 * @return the deep link
	 * @throws ApiException exceptions that could occorred (logs for debug and for
	 *                      the user where already created)
	 */
	public RedirectLinkResponse authorizationLinkCredential(UserPrincipal userPrincipal, String redirect_uri) throws ApiException {
		RedirectLinkResponse response;
		String id = userPrincipal.getId();

		Optional<User> optionalUserOID4VP = userService.getUserById(id);
		if (optionalUserOID4VP.isEmpty()) {
			String logMessage = SignerError.UserNotFound.getCode()
					+ "(authorizationLinkCredential in CSCCredentialsService.class): User that requested new Credential not found.";
			logger.error(logMessage);
			throw new ApiException(SignerError.UserNotFound, "Failed to find user {}", id);
		}

		try {
			response = this.verifierClient.initPresentationTransaction(optionalUserOID4VP.get().getId(), VerifierClient.Authorization, redirect_uri);
			return response;
		} catch (ApiException e) {
			loggerUtil.logsUser(0, id, 6, e.getMessage());
			throw e;
		} catch (Exception e) {
			String logMessage = SignerError.UnexpectedError.getCode()
					+ " (authorizationLinkCredential in CSCCredentialsService.class) " + e.getMessage();
			logger.error(logMessage);
			loggerUtil.logsUser(0, id, 6, e.getMessage());
			throw new ApiException(SignerError.UnexpectedError, e.getMessage());

		}
	}
}
