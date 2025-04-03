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

package eu.europa.ec.eudi.signer.rssp.csc.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import eu.europa.ec.eudi.signer.common.AccessCredentialDeniedException;
import eu.europa.ec.eudi.signer.common.FailedConnectionVerifier;
import eu.europa.ec.eudi.signer.common.TimeoutException;
import eu.europa.ec.eudi.signer.csc.payload.*;
import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.rssp.common.config.AuthProperties;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.common.error.VPTokenInvalid;
import eu.europa.ec.eudi.signer.rssp.common.error.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.rssp.csc.services.CSCCredentialsService;
import eu.europa.ec.eudi.signer.rssp.security.CurrentUser;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;

import javax.validation.Valid;

/**
 * Credentials endpoints from:
 * From section 11.4/11.5 of the CSC API V_1.0.4.0 spec
 */
@RestController
@RequestMapping(value = "/credentials")
public class CSCCredentialsController {
	private static final Logger log = LoggerFactory.getLogger(CSCCredentialsController.class);

	private final CSCCredentialsService credentialsService;
	private final AuthProperties authProperties;

	@Autowired
	public CSCCredentialsController(CSCCredentialsService credentialsService, AuthProperties authProperties) {
		this.credentialsService = credentialsService;
		this.authProperties = authProperties;
	}

	@PostMapping("info")
	@ResponseStatus(HttpStatus.OK)
	public CSCCredentialsInfoResponse info(@CurrentUser UserPrincipal userPrincipal,
			@Valid @RequestBody CSCCredentialsInfoRequest infoRequest) {
		return credentialsService.getCredentialsInfoFromAlias(userPrincipal,
				infoRequest);
	}

	@GetMapping("authorizationLink")
	@ResponseStatus(HttpStatus.OK)
	public RedirectLinkResponse authorizeLink(@CurrentUser UserPrincipal userPrincipal, @RequestParam String redirect_uri) {
		try {
			return credentialsService.authorizationLinkCredential(userPrincipal, redirect_uri);
		} catch (ApiException e) {
			return new RedirectLinkResponse();
		}
	}

	@PostMapping("authorize")
	@ResponseStatus(HttpStatus.OK)
	public ResponseEntity<?> authorize(
			@CurrentUser UserPrincipal userPrincipal,
			@Valid @RequestBody CSCCredentialsAuthorizeRequest authorizeRequest) {
		try {
			CSCCredentialsAuthorizeResponse response = credentialsService.authorizeCredential(userPrincipal, authorizeRequest);
			return ResponseEntity.ok(response);
		} catch (FailedConnectionVerifier e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(SignerError.FailedConnectionToVerifier.getFormattedMessage());
		} catch (TimeoutException e) {
			return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT)
					.body(SignerError.ConnectionVerifierTimedOut.getFormattedMessage());
		} catch (AccessCredentialDeniedException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
		} catch (VerifiablePresentationVerificationException e) {
			return ResponseEntity.badRequest().body(e.getError().getFormattedMessage() + " (" + e.getMessage() + ")");
		} catch (VPTokenInvalid e) {
			return ResponseEntity.badRequest().body(e.getError().getFormattedMessage());
		} catch (ApiException e) {
			SignerError error = (SignerError) e.getApiError();
			return ResponseEntity.badRequest().body(error.getFormattedMessage() + " (" + e.getMessage() + ")");
		} catch (Exception e) {
			String logMessage = SignerError.UnexpectedError.getCode() + ": " + e.getMessage();
			log.error(logMessage);
			LoggerUtil.logsUser(this.authProperties.getDatasourceUsername(),
					this.authProperties.getDatasourcePassword(), 0, userPrincipal.getId(), 6, "");
			return ResponseEntity.badRequest().body(SignerError.UnexpectedError.getFormattedMessage());
		}
	}
}
