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

import eu.europa.ec.eudi.signer.rssp.api.services.CredentialService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import eu.europa.ec.eudi.signer.rssp.api.services.UserService;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.common.error.VPTokenInvalid;
import eu.europa.ec.eudi.signer.rssp.common.error.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.rssp.entities.Credential;
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

	private static final Logger logger = LoggerFactory.getLogger(CSCCredentialsService.class);

	// Allowed values for the certificates attribute: not used in payload but
	// derived in validation
	public enum CertificatesRequest {
		none, single, chain
	}

	private final OpenId4VPService openId4VPService;
	private final UserService userService;
	private final CSCSADProvider sadProvider;
	private final CredentialService credentialService;
	private final LoggerUtil loggerUtil;

	public CSCCredentialsService(@Autowired OpenId4VPService openId4VPService,
								 @Autowired UserService userService,
								 @Autowired CSCSADProvider sadProvider,
								 @Autowired CredentialService credentialService,
								 @Autowired LoggerUtil loggerUtil) {
		this.openId4VPService = openId4VPService;
		this.userService = userService;
		this.sadProvider = sadProvider;
		this.credentialService = credentialService;
		this.loggerUtil = loggerUtil;
	}

	public CSCCredentialsInfoResponse getCredentialsInfoFromAlias(UserPrincipal userPrincipal, CSCCredentialsInfoRequest infoRequest) {

		final String credentialAlias = infoRequest.getCredentialID();

		// retrieve the credential that belongs to the user with the given alias
		final Credential credential = this.credentialService.getCredentialWithAlias(userPrincipal.getId(), credentialAlias)
			  .orElseThrow(
					() -> new ApiException(CSCInvalidRequest.InvalidCredentialId,
						  "No credential found with the given Id", credentialAlias));

		CSCCredentialsInfoResponse response = new CSCCredentialsInfoResponse();

		response.setAuthMode(CSCConstants.CSC_AUTH_MODE);
		response.setDescription(credential.getDescription());
		response.setMultisign(CSCConstants.CSC_MAX_REQUEST_SIGNATURES);
		response.setSCAL(CSCConstants.CSC_SCAL);
		response.setKey(buildKeyInfo(credential));
		response.setCert(getCertInCredentialInfoResponse(credential, infoRequest.getCertificates(), infoRequest.isCertInfo()));
		if (infoRequest.isAuthInfo()) {
			response.setPIN(buildPINInfo());
			response.setOTP(buildOTPInfo());
		}
		return response;
	}

	private CSCCredentialsInfoResponse.Cert getCertInCredentialInfoResponse(Credential credential, String certificates, boolean isCertInfo){
		CSCCredentialsInfoResponse.Cert cert = new CSCCredentialsInfoResponse.Cert();
		List<String> cscCertificates = new ArrayList<>();

		final String pemCertificate = credential.getCertificate();
		switch (toCertsRequest(certificates)) {
			case none:
				break;
			case single:
				cscCertificates.add(pemCertificate); // certificates are already stored as PEM strings which are Base64 encoded
				break;
			case chain:
				throw new IllegalArgumentException("Not Yet Implmented");
		}
		cert.setCertificates(cscCertificates);

		final X509Certificate x509Certificate = credentialService.pemToX509(pemCertificate);
		if (isCertInfo) {
			addCertInfo(cert, x509Certificate);
		}
		if (credentialService.isCertificateExpired(x509Certificate)) {
			cert.setStatus(CertificateStatus.expired.name());
		} else {
			cert.setStatus(CertificateStatus.valid.name());
		}
		return cert;
	}

	/** helper to convert the string certificates property to an enum */
	private CertificatesRequest toCertsRequest(String certificates) {
		if (StringUtils.hasText(certificates)) {
			try {
				return CertificatesRequest.valueOf(certificates);
			} catch (IllegalArgumentException e) {
				throw new ApiException(CSCInvalidRequest.InvalidCertificatesParameter);
			}
		}
		return CertificatesRequest.single; // certificates is optional and defaults to single
	}

	/**
	 * Update info about the cert in the response
	 * According to the CSC standard, these properties are only set when the
	 * certInfo property
	 * is true in the request
	 */
	private void addCertInfo(CSCCredentialsInfoResponse.Cert cert, X509Certificate x509Certificate) {
		cert.setIssuerDN(x509Certificate.getIssuerX500Principal().getName());
		cert.setSubjectDN(x509Certificate.getSubjectX500Principal().getName());
		cert.setSerialNumber(String.valueOf(x509Certificate.getSerialNumber()));
		cert.setValidFrom(CertificateUtils.x509Date(x509Certificate.getNotBefore())); // per CSC spec: encoded as GeneralizedTime (RFC 5280 [8]) e.g. “YYYYMMDDHHMMSSZ”
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

	/**
	 * Validate the PIN provided and generate a SAD token for the user to authorize
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
		return authorizeCredentialWithOID4VP(user.get(), authorizeRequest, response);
	}

	private CSCCredentialsAuthorizeResponse authorizeCredentialWithOID4VP(User user, CSCCredentialsAuthorizeRequest authorizeRequest, CSCCredentialsAuthorizeResponse response)
			throws FailedConnectionVerifier, TimeoutException, ApiException, AccessCredentialDeniedException, VerifiablePresentationVerificationException, VPTokenInvalid {
		final String credentialID = authorizeRequest.getCredentialID();
		User loaded = null;

		try {
			Map<Integer, String> logsMap = new HashMap<>();
			System.out.println(authorizeRequest.getCode());
			if(authorizeRequest.getCode() != null)
				loaded = openId4VPService.getVPTokenFromVerifierAndReturnUser(user.getId(), VerifierClient.Authorization, authorizeRequest.getCode(), logsMap);
			else
				loaded = openId4VPService.pollVPTokenAndReturnUser(user.getId(), VerifierClient.Authorization, logsMap);

			for (Entry<Integer, String> l : logsMap.entrySet())
				loggerUtil.logsUser(1, user.getId(), l.getKey(), l.getValue());

		} catch (FailedConnectionVerifier e) {
			logger.error(SignerError.FailedConnectionToVerifier.getFormattedMessage());
			loggerUtil.logsUser(0, user.getId(), 6, "");
			throw e;

		} catch (TimeoutException e) {
			logger.error(SignerError.ConnectionVerifierTimedOut.getFormattedMessage());
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
	 * @throws ApiException exceptions that could occurred (logs for debug and for
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
			response = this.openId4VPService.getRedirectLink(optionalUserOID4VP.get().getId(), VerifierClient.Authorization, redirect_uri);
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
