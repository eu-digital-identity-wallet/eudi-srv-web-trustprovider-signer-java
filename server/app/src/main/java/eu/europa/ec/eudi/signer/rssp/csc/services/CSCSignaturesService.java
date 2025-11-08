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

import eu.europa.ec.eudi.signer.rssp.crypto.CryptoSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import eu.europa.ec.eudi.signer.csc.error.CSCInvalidRequest;
import eu.europa.ec.eudi.signer.csc.payload.CSCSignaturesSignHashRequest;
import eu.europa.ec.eudi.signer.csc.payload.CSCSignaturesSignHashResponse;
import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.rssp.api.services.CredentialService;
import eu.europa.ec.eudi.signer.rssp.api.services.UserService;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.entities.Credential;
import eu.europa.ec.eudi.signer.rssp.entities.User;
import eu.europa.ec.eudi.signer.rssp.crypto.CryptoService;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;

import jakarta.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class CSCSignaturesService {

	private static final Logger log = LoggerFactory.getLogger(CSCSignaturesService.class);
	private final CredentialService credentialService;
	private final UserService userService;
	private final CryptoSigner cryptoSigner;
	private final CSCSADProvider sadProvider;
	private final LoggerUtil loggerUtil;

	public CSCSignaturesService(CredentialService credentialService, UserService userService,
								CryptoSigner cryptoSigner, CSCSADProvider sadProvider, LoggerUtil loggerUtil) {
		this.credentialService = credentialService;
		this.userService = userService;
		this.cryptoSigner = cryptoSigner;
		this.sadProvider = sadProvider;
		this.loggerUtil = loggerUtil;
	}

	/**
	 * Sign the provided hash with the credential specified in the request
	 */
	public CSCSignaturesSignHashResponse signHash(UserPrincipal userPrincipal,
			@Valid @RequestBody CSCSignaturesSignHashRequest signHashRequest) {

		CSCSignaturesSignHashResponse response = new CSCSignaturesSignHashResponse();
		String pdfName = signHashRequest.getClientData();
		final String credentialAlias = signHashRequest.getCredentialID();
		final String sad = signHashRequest.getSAD();

		Optional<User> user = userService.getUserById(userPrincipal.getId());
		if (user.isEmpty()) {
			log.error(
					"{} (signHash in CSCSignaturesService.class): User not found.",
					SignerError.UserNotFound.getCode());
			throw new ApiException(SignerError.UserNotFound, "User not found.");
		}

		final Credential credential = credentialService
				.getCredentialWithAlias(userPrincipal.getId(), credentialAlias).orElseThrow(
						() -> {
							loggerUtil.logsUser(0, userPrincipal.getId(), 6, "");
							LoggerUtil.desc = "";
							return new ApiException(CSCInvalidRequest.InvalidCredentialId, "No credential found with the given Id", credentialAlias);
						});
		try {
			// we know SAD is not empty thanks to annotations in the DTO, but is it valid?
			// if it is expired or otherwise invalid, the provider will throw the right
			// exception for the CSC standard
			sadProvider.validateSAD(sad);
		} catch (Exception e) {
			log.error("{} (signHash in CSCSignaturesService.class.class): SAD not validated.",
					SignerError.FailedToValidateSAD.getCode());
			loggerUtil.logsUser(0, userPrincipal.getId(), 6, "");
			LoggerUtil.desc = "";
			throw new ApiException(SignerError.FailedToValidateSAD);
		}

		try {
			List<String> signedHashes = new ArrayList<>();
			for (String hash : signHashRequest.getHash()) {
				String signedData = cryptoSigner.signWithPemCertificate(
						hash,
						credential.getCertificate(),
						credential.getCertificateChains(),
						credential.getPrivateKeyHSM(),
						signHashRequest.getSignAlgo(),
						signHashRequest.getSignAlgoParams());
				signedHashes.add(signedData); // assumes UTF8
			}
			response.setSignatures(signedHashes);
			LoggerUtil.desc = LoggerUtil.desc + " | CMS Signed Data Bytes: " + signedHashes;
			LoggerUtil.desc = LoggerUtil.desc + " | File Name: " + pdfName;
			loggerUtil.logsUser(1, userPrincipal.getId(), 6, LoggerUtil.desc);
			LoggerUtil.desc = "";
		} catch (Exception e) {
			log.error("{} (signHash in CSCSignaturesService.class.class): Failed to sign.",
					SignerError.FailedSigningData.getCode());
			loggerUtil.logsUser(0, userPrincipal.getId(), 6, "");
			throw e;
		}
		return response;
	}
}
