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

package eu.europa.ec.eudi.signer.rssp.api.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.csc.payload.CredentialInfo;
import eu.europa.ec.eudi.signer.rssp.api.services.CredentialService;
import eu.europa.ec.eudi.signer.rssp.api.services.UserService;
import eu.europa.ec.eudi.signer.rssp.common.config.AuthProperties;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.entities.Credential;
import eu.europa.ec.eudi.signer.rssp.entities.User;
import eu.europa.ec.eudi.signer.rssp.security.CurrentUser;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;
import java.util.List;

@RestController
@RequestMapping(value = "/credentials")
public class CredentialController {
	private static final Logger logger = LogManager.getLogger(CredentialController.class);
	private final CredentialService credentialService;
	private final UserService userService;
	private final LoggerUtil loggerUtil;

	public CredentialController(@Autowired final CredentialService credentialService, @Autowired final UserService userService,
								@Autowired LoggerUtil loggerUtil) {
		this.credentialService = credentialService;
		this.userService = userService;
		this.loggerUtil = loggerUtil;
	}

	/**
	 * Function that allows to create a new credential. In this project "credential"
	 * includes a key pair and a certificate.
	 * Exception: if the user can't be found
	 * Exception: if a credential with the same alias already exists.
	 * 
	 * @param userPrincipal the user authenticated
	 * @param alias         the alias of the credential to create
	 */
	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public ResponseEntity<?> createCredential(@CurrentUser UserPrincipal userPrincipal,
			@RequestParam("alias") String alias) {

		alias = alias.replaceAll("[\n\r]", "_");
        logger.info("Trying to create the credential {}", alias);

		String id = userPrincipal.getId();
		Optional<User> user = userService.getUserById(id);

		if (user.isEmpty()) {
			String logMessage = SignerError.UserNotFound.getCode()
					+ "(createCredential in CredentialController.class): User that requested new Credential not found.";
			logger.error(logMessage);
			return ResponseEntity.badRequest().body(SignerError.UserNotFound.getFormattedMessage());
		}

		try {
			String owner = user.get().getId();
			String countryCode = user.get().getIssuingCountry();
			String givenName = userPrincipal.getGivenName();
			String surname = userPrincipal.getSurname();
			String subjectDN = userPrincipal.getName();
			Credential credential = credentialService.createCredential(owner, givenName, surname, subjectDN,
					alias, countryCode);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec pKeySpec = new X509EncodedKeySpec(credential.getPublicKeyHSM());
			RSAPublicKey pk = (RSAPublicKey) keyFactory.generatePublic(pKeySpec);
			String info = "Public Key info - Algorithm: " + pk.getAlgorithm() + " " + pk.getModulus().bitLength()
				  + " bits | Modulus: " + pk.getModulus() + " | Exponent: " + pk.getPublicExponent();
			loggerUtil.logsUser(1, owner, 3, info);

			String info2 = "Certificate Alias: " + credential.getAlias() + " | Subject DN: " + credential.getSubjectDN()
					+ " | Issuer DN: " + credential.getIssuerDN() + " | Valid From: " + credential.getValidFrom()
					+ " | Valid To: " + credential.getValidTo();
			loggerUtil.logsUser(1, id, 1, info2);
			return new ResponseEntity<>(HttpStatus.CREATED);
		} catch (ApiException e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		} catch (Exception e) {
			String logMessage = SignerError.UnexpectedError.getCode() + " (createCredential in CredentialController.class) " + e.getMessage();
			logger.error(logMessage);
			loggerUtil.logsUser(0, id, 1, "");
			return ResponseEntity.badRequest().body(SignerError.UnexpectedError.getFormattedMessage());
		}
	}

	@PostMapping("list")
	@ResponseStatus(HttpStatus.OK)
	public List<CredentialInfo> list(@CurrentUser UserPrincipal userPrincipal) {
		return credentialService.listCredentials(userPrincipal.getId());
	}

	/**
	 * Function that allows the authenticated user to delete one of their credential
	 * 
	 * @param userPrincipal the user authenticated
	 * @param alias         the alias of the credential to delete
	 */
	@DeleteMapping("/{alias}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public ResponseEntity<?> deleteCredential(@CurrentUser UserPrincipal userPrincipal,
			@PathVariable(value = "alias") String alias) {
		try {
			logger.info("Trying to delete the credential {}", alias);
			String ownerId = userPrincipal.getId();
			credentialService.deleteCredentials(ownerId, alias);
			return ResponseEntity.ok().build();
		} catch (ApiException e) {
			// if the aux functions sent an api exception, the logs were already written
			// the ApiException also have a set message to be shown to the user
			return ResponseEntity.badRequest().body(e.getMessage());
		} catch (Exception e) {
			String logMessage = SignerError.UnexpectedError.getCode()
					+ " (deleteCredential in CredentialController.class) " + e.getMessage();
			logger.error(logMessage);
			loggerUtil.logsUser(0, userPrincipal.getId(), 2, "");
			return ResponseEntity.badRequest().body(SignerError.UnexpectedError.getFormattedMessage());
		}
	}
}
