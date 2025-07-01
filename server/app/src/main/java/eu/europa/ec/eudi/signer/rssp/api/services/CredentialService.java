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

package eu.europa.ec.eudi.signer.rssp.api.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.csc.payload.CredentialInfo;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.entities.Credential;
import eu.europa.ec.eudi.signer.rssp.crypto.CryptoService;
import eu.europa.ec.eudi.signer.rssp.repository.CredentialRepository;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class CredentialService {
	private static final Logger logger = LogManager.getLogger(CredentialService.class);

	private final CredentialRepository credentialRepository;
	private final CryptoService cryptoService;
	private final LoggerUtil loggerUtil;

	public CredentialService(@Autowired CredentialRepository credentialRepository, @Autowired CryptoService cryptoService, @Autowired LoggerUtil loggerUtil) {
		this.credentialRepository = credentialRepository;
		this.cryptoService = cryptoService;
		this.loggerUtil = loggerUtil;
	}

	/**
	 * Creates a new certificate and keypair combinations and stores them in the
	 * repository.
	 * Exception (Api Exception): if a credential with the same alias already exists
	 *
	 * @param owner       the id of the user that owns this credential
	 * @param givenName   the given name of the user that owns this credential (used
	 *                    to create the certificate)
	 * @param surname     the surname of the user that owns this credential (used to
	 *                    create the certificate)
	 * @param subjectDN   name of the subject, used in the certificate
	 * @param alias       the name by which the credential will be associated
	 * @param countryCode the countryCode of the user (from the VP Token), that will
	 *                    determine which CA will sign the certificate
	 * @return the credential created
	 */
	public Credential createCredential(String owner, String givenName, String surname, String subjectDN,
			String alias, String countryCode) throws Exception {
		if (this.credentialRepository.findByOwnerAndAlias(owner, alias).isPresent()) {
			String logMessage = SignerError.CredentialAliasAlreadyExists.getCode()
					+ " (createCredential in CredentialService.class) "
					+ SignerError.CredentialAliasAlreadyExists.getDescription();
			logger.error(logMessage);
			loggerUtil.logsUser(0, owner, 1, SignerError.CredentialAliasAlreadyExists.getDescription());

			throw new ApiException(SignerError.CredentialAliasAlreadyExists,
					"The credential alias " + alias + " chosen is not valid. The aliases must be unique.");
		}

		Credential credential = cryptoService.createCredential(owner, givenName, surname, subjectDN, alias,
				countryCode);
		credential.setCreatedAt(Instant.now());
		credentialRepository.save(credential);
		return credential;
	}

	/**
	 * Deletes the credentials with the specified Id.
	 * Throws an exception if the credential with the credentialAlias of the owner
	 * was not found.
	 *
	 * @param ownerId         the id of the owner of the credential to delete
	 * @param credentialAlias the alias of the credential to delete
	 */
	public void deleteCredentials(String ownerId, String credentialAlias) {
		Optional<Credential> credential = credentialRepository.findByOwnerAndAlias(ownerId, credentialAlias);

		if (credential.isEmpty()) {
			String logMessage = SignerError.CredentialNotFound.getCode()
					+ " (deleteCredential in CredentialService.class) "
					+ SignerError.CredentialNotFound.getDescription();
			logger.error(logMessage);
			loggerUtil.logsUser(0, ownerId, 2, "");
			throw new ApiException(SignerError.CredentialNotFound,
					"Attempted to delete the credential " + credentialAlias + ", that does not exist.");
		}
		String info = "Certificate Alias: " + credential.get().getAlias()
				+ " | Subject DN: " + credential.get().getSubjectDN()
				+ " | Issuer DN: " + credential.get().getIssuerDN()
				+ " | Valid From: " + credential.get().getValidFrom()
				+ " | Valid To: " + credential.get().getValidTo();
		credentialRepository.deleteByOwnerAndAlias(ownerId, credentialAlias);
		loggerUtil.logsUser(1, ownerId, 2, info);
	}

	// ...............................

	public List<CredentialInfo> listCredentials(String ownerId) {
		final List<Credential> credentialsList = credentialRepository.findByOwner(ownerId);
		List<CredentialInfo> credentialsInfo = new ArrayList<>();
		for (Credential ac : credentialsList) {
			CredentialInfo ci = new CredentialInfo(ac.getAlias(), ac.getIssuerDN(), ac.getSubjectDN(),
					ac.getValidFrom(), ac.getValidTo());
			credentialsInfo.add(ci);
		}
		return credentialsInfo;
	}

	public Page<Credential> getCredentialsByOwner(String owner, Pageable pageable) {
		return credentialRepository.findByOwner(owner, pageable);
	}

	public Optional<Credential> getCredentialWithAlias(String owner, String alias) {
		return credentialRepository.findByOwnerAndAlias(owner, alias);
	}

}
