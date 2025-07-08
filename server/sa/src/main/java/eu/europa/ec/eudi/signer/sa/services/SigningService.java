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

package eu.europa.ec.eudi.signer.sa.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import eu.europa.ec.eudi.signer.common.AccessCredentialDeniedException;
import eu.europa.ec.eudi.signer.common.FailedConnectionVerifier;
import eu.europa.ec.eudi.signer.common.TimeoutException;
import eu.europa.ec.eudi.signer.csc.payload.RedirectLinkResponse;
import eu.europa.ec.eudi.signer.sa.client.RSSPClient;
import eu.europa.ec.eudi.signer.sa.client.ClientContext;
import eu.europa.ec.eudi.signer.sa.config.RSSPClientConfig;
import eu.europa.ec.eudi.signer.sa.error.InternalErrorException;
import eu.europa.ec.eudi.signer.sa.pdf.PdfSupport;

import java.io.IOException;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;

@Service
public class SigningService {

	private static final Logger log = LoggerFactory.getLogger(SigningService.class);
	final RSSPClient rsspClient;
	PdfSupport pdfSupport;
	private final FileStorageService fileStorageService;

	public SigningService(RSSPClientConfig rsspClientConfig,
			FileStorageService fileStorageService) {
		rsspClient = new RSSPClient(rsspClientConfig);
		pdfSupport = new PdfSupport(rsspClient);
		this.fileStorageService = fileStorageService;
	}

	/**
	 * Function that allows to get a link to redirect the user to the EUDI Wallet,
	 * after the authorization request to the verifier is executed
	 * 
	 * @param authorizationHeader the authorization header
	 * @return the link to redirect to the EUDI Wallet
	 */
	public RedirectLinkResponse getOIDRedirectLink(String authorizationHeader, String redirect_uri) {
		ClientContext context = new ClientContext();
		context.setAuthorizationHeader(authorizationHeader);
		rsspClient.setContext(context);
		return pdfSupport.getOIDRedirectLink(redirect_uri);
	}

	/**
	 * Function that allows to sign a file
	 * 
	 * @param originalFileName    the name of the original file
	 * @param credentialAlias     the alias of the credential used to sign the pdf
	 * @param authorizationHeader the authorization header
	 * @return
	 * @throws InternalErrorException
	 * @throws FailedConnectionVerifier
	 * @throws TimeoutException
	 * @throws AccessCredentialDeniedException
	 * @throws Exception
	 */
	public String signFile(String originalFileName, String credentialAlias, String authorizationHeader, String responseCode)
			throws InternalErrorException, FailedConnectionVerifier, TimeoutException, AccessCredentialDeniedException,
			Exception {
		String signedFileName;
		try {
			Path originalFilePath = fileStorageService.getFilePath(originalFileName);
			String baseName = originalFilePath.getFileName().toString();
			signedFileName = StringUtils.stripFilenameExtension(baseName) + "_signed.pdf";
			Path signedFilePath = fileStorageService.newFilePath(signedFileName);
			ClientContext context = new ClientContext();
			context.setAuthorizationHeader(authorizationHeader);
			context.setCredentialID(credentialAlias);
			rsspClient.setContext(context);
			pdfSupport.signDetached(originalFilePath.toFile(), signedFilePath.toFile(), responseCode);
		} catch (IOException | NoSuchAlgorithmException e) {
			log.error("Internal error in Signing Application", e);
			throw new InternalErrorException("Internal error in Signing Application", e);
		} catch (AccessCredentialDeniedException e) {
			throw e;
		} catch (Exception e) {
			log.error("Error: ", e);
			throw e;
		} finally {
			rsspClient.setContext(null); // clear it just in case it gets resused
		}
		return signedFileName;
	}
}
