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

package eu.europa.ec.eudi.signer.sa.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import eu.europa.ec.eudi.signer.common.AccessCredentialDeniedException;
import eu.europa.ec.eudi.signer.common.FailedConnectionVerifier;
import eu.europa.ec.eudi.signer.common.TimeoutException;
import eu.europa.ec.eudi.signer.csc.payload.RedirectLinkResponse;
import eu.europa.ec.eudi.signer.sa.error.InvalidRequestException;
import eu.europa.ec.eudi.signer.sa.payload.SignedFileResponse;
import eu.europa.ec.eudi.signer.sa.services.SigningService;
import eu.europa.ec.eudi.signer.sa.services.FileStorageService;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping(value = "/sa")
public class SigningController {
	private static final Logger log = LoggerFactory.getLogger(SigningController.class);

	private final SigningService signingService;
	private final FileStorageService fileStorageService;
	public Environment env;

	public SigningController(SigningService signingService,
			FileStorageService fileStorageService, @Autowired Environment env) {
		this.signingService = signingService;
		this.fileStorageService = fileStorageService;
		this.env = env;
	}

	/**
	 * Function that allows to get the link to redirect the user to the EUDI
	 * Wallet, after the authorization request to the verifier is executed
	 * 
	 * @param authorizationHeader the authorization header
	 * @return the link to redirect the user to the EUDI Wallet
	 */
	@GetMapping("/getOIDRedirectLink")
	public ResponseEntity<RedirectLinkResponse> getOIDRedirectLink(
			@RequestHeader("Authorization") String authorizationHeader, @RequestParam String redirect_uri) {

		if (!StringUtils.hasText(authorizationHeader)) {
			throw new InvalidRequestException("Expected an authorization header");
		}

		String redirect_uri_decoded = URLDecoder.decode(redirect_uri, StandardCharsets.UTF_8);
		log.info("redirect_uri from Request: {}", redirect_uri_decoded);
		RedirectLinkResponse res = this.signingService.getOIDRedirectLink(authorizationHeader, redirect_uri_decoded);
		return ResponseEntity.ok(res);
	}

	/**
	 * Function that allows the user to upload a file and sign it.
	 * Exception if failed to Connect to the Verifier
	 * Exception if the connect to the verifier timed out.
	 * Exception if the access to the credential was denied.
	 * 
	 * @param authorizationHeader the authorization header
	 * @param file                the file to sign
	 * @param credentialAlias     the alias of the credential to use to sign the
	 *                            document
	 * @return the signed file
	 */
	@PostMapping("/signFile")
	public Object uploadFile(@RequestHeader("Authorization") String authorizationHeader,
							 @RequestParam("file") MultipartFile file,
							 @RequestParam("credential") String credentialAlias,
							 @RequestParam(value = "response_code", required = false) String responseCode) {

		if (!StringUtils.hasText(authorizationHeader)) {
			throw new InvalidRequestException("Expected an authorization header");
		}

		try {
			String originalFileName = fileStorageService.storeFile(file);
			String signedFileName = signingService.signFile(originalFileName, credentialAlias, authorizationHeader, responseCode);
			String saUrl = env.getProperty("ASSINA_SA_BASE_URL");
			if (saUrl == null)
				saUrl = "http://localhost:8083";
			String fileDownloadUri = saUrl + "/sa/downloadFile/" + signedFileName;
			return new SignedFileResponse(signedFileName, fileDownloadUri, file.getContentType(), file.getSize());
		} catch (FailedConnectionVerifier e) {
			log.error("Exception: Failed connection to Verifier.");
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
		} catch (TimeoutException e) {
			log.error("Exception: Waiting response from Verifier timed out.");
			return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT).body(e.getMessage());
		} catch (AccessCredentialDeniedException e) {
			log.error("Exception: Authorization Failed. Access denied.");
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
		} catch (Exception e) {
			log.error("Error when trying to obtain the vp_token.");
			return ResponseEntity.badRequest().body(e.getMessage());
		}
	}

	/**
	 * Function that allows the user to download the file signed
	 * 
	 * @param fileName the name of the file to download
	 * @param request  the request
	 * @return the signed file
	 */
	@GetMapping("/downloadFile/{fileName:.+}")
	public ResponseEntity<Resource> downloadFile(@PathVariable String fileName, HttpServletRequest request) {
		// Load file as Resource
		Resource resource = fileStorageService.loadFileAsResource(fileName);

		// Try to determine file's content type
		String contentType = null;
		try {
			contentType = request.getServletContext().getMimeType(resource.getFile().getAbsolutePath());
		} catch (IOException ex) {
			log.info("Could not determine file type.");
		}

		// Fallback to the default content type if type could not be determined
		if (contentType == null) {
			contentType = "application/octet-stream";
		}

		return ResponseEntity.ok()
				.contentType(MediaType.parseMediaType(contentType))
				.header(HttpHeaders.CONTENT_DISPOSITION,
						"attachment; filename=\"" + resource.getFilename() + "\"")
				.body(resource);
	}

}
