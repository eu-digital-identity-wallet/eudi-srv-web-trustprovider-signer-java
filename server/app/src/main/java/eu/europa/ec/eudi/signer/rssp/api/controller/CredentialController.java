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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.rssp.api.services.CredentialService;
import eu.europa.ec.eudi.signer.rssp.api.services.UserService;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.entities.User;
import eu.europa.ec.eudi.signer.rssp.security.CurrentUser;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;

import java.util.Optional;

/* REST controller that defines endpoints for certificate and key pair management not covered by the CSC API v1.0 specification. */
@RestController
@RequestMapping(value = "/credentials")
public class CredentialController {
	private static final Logger logger = LoggerFactory.getLogger(CredentialController.class);
	private final CredentialService credentialService;
	private final UserService userService;
	private final LoggerUtil loggerUtil;

	public CredentialController(@Autowired final CredentialService credentialService, @Autowired final UserService userService, @Autowired LoggerUtil loggerUtil) {
		this.credentialService = credentialService;
		this.userService = userService;
		this.loggerUtil = loggerUtil;
	}

	/**
	 * Function that allows to create a new credential. In this project "credential"
	 * includes a key pair and a certificate.
	 * Exception: if the user can't be found
	 * Exception: if a credential with the same alias already exists
	 * @param userPrincipal the user authenticated
	 * @param alias         the alias of the credential to create
	 */
	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public ResponseEntity<?> createCredential(@CurrentUser UserPrincipal userPrincipal, @RequestParam("alias") String alias) {
		String id = userPrincipal.getId();
		Optional<User> optionalUser = userService.getUserById(id);
		if (optionalUser.isEmpty()) {
			logger.error("{}: User that requested new Credential not found.", SignerError.UserNotFound.getCode());
			return ResponseEntity.badRequest().body(SignerError.UserNotFound.getFormattedMessage());
		}

		alias = alias.replaceAll("[\n\r]", "_");
		logger.info("Trying to create the credential {} for the user {}", alias, userPrincipal.getId());

		User user = optionalUser.get();
		String owner = user.getId();
		try {
			String countryCode = user.getIssuingCountry();
			String givenName = userPrincipal.getGivenName();
			String surname = userPrincipal.getSurname();
			String subjectDN = userPrincipal.getName();
			credentialService.createCredential(owner, givenName, surname, subjectDN, alias, countryCode);
			logger.info("Created the credential {} for the user {}", alias, userPrincipal.getName());
			return new ResponseEntity<>(HttpStatus.CREATED);
		} catch (ApiException e) {
			//loggerUtil.logsUser(0, owner, 1, e.getApiError().getDescription());
			return ResponseEntity.badRequest().body(e.getMessage());
		} catch (Exception e) {
			String logMessage = SignerError.UnexpectedError.getCode() + " " + e.getMessage();
			logger.error(logMessage);
			loggerUtil.logsUser(0, id, 1, "");
			return ResponseEntity.badRequest().body(SignerError.UnexpectedError.getFormattedMessage());
		}
	}

	@PostMapping("list")
	@ResponseStatus(HttpStatus.OK)
	public ResponseEntity<?> list(@CurrentUser UserPrincipal userPrincipal) {
		String id = userPrincipal.getId();
		Optional<User> optionalUser = userService.getUserById(id);
		if (optionalUser.isEmpty()) {
			logger.error("{}: User that requested list of credentials not found.", SignerError.UserNotFound.getCode());
			return ResponseEntity.badRequest().body(SignerError.UserNotFound.getFormattedMessage());
		}

		logger.info("Retrieving the list of certificates of the user {}", id);
		return ResponseEntity.ok(credentialService.listCredentials(id));
		// return credentialService.listCredentials(id);
	}

	/**
	 * Function that allows the authenticated user to delete one of their credential
	 * 
	 * @param userPrincipal the user authenticated
	 * @param alias         the alias of the credential to delete
	 */
	@DeleteMapping("/{alias}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public ResponseEntity<?> deleteCredential(@CurrentUser UserPrincipal userPrincipal, @PathVariable(value = "alias") String alias) {
		try {
			logger.info("Trying to delete the credential {}", alias);
			String owner = userPrincipal.getId();
			Optional<User> optionalUser = userService.getUserById(owner);
			if (optionalUser.isEmpty()) {
				logger.error("{}: User that requested credential to be deleted not found.", SignerError.UserNotFound.getCode());
				return ResponseEntity.badRequest().body(SignerError.UserNotFound.getFormattedMessage());
			}

			credentialService.deleteCredentials(owner, alias);
			return ResponseEntity.ok().build();
		} catch (ApiException e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		} catch (Exception e) {
			logger.error(SignerError.UnexpectedError.getFormattedMessage());
			loggerUtil.logsUser(0, userPrincipal.getId(), 2, "");
			return ResponseEntity.badRequest().body(SignerError.UnexpectedError.getFormattedMessage());
		}
	}
}
