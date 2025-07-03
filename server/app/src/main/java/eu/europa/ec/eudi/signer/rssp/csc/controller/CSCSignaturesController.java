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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.ec.eudi.signer.csc.payload.*;
import eu.europa.ec.eudi.signer.rssp.csc.services.CSCSignaturesService;
import eu.europa.ec.eudi.signer.rssp.security.CurrentUser;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;

import jakarta.validation.Valid;

/**
 * Signatures endpoints from:
 * From section 11.9 of the CSC API V_1.0.4.0 spec
 */
@RestController
@RequestMapping(value = "/signatures")
public class CSCSignaturesController {
	private CSCSignaturesService signaturesService;

	@Autowired
	public CSCSignaturesController(CSCSignaturesService signaturesService) {
		this.signaturesService = signaturesService;
	}

	/**
	 * Calculate the remote digital signature of one or multiple hash values
	 * provided in input.
	 * This method requires credential authorization in the form of Signature
	 * Activation Data (SAD).
	 * The signature application SHALL first pass to this method the SAD obtained
	 * from
	 * either a credential/authorize, as defined in section 11.6, or a
	 * oauth2/authorize calls, as
	 * defined in section 8.3.2, depending on the type of supported authorization
	 * mechanisms
	 * associated with the credential.
	 * In case of multi-signature transactions, the SAD SHALL be updated with
	 * credentials/extendTransaction, as defined in section 11.7, every time this
	 * method is
	 * invoked until the maximum number of authorized signatures has been generated.
	 *
	 * Example request:
	 * POST /csc/v1/signatures/signHash HTTP/1.1
	 * Host: service.domain.org
	 * Content-Type: application/json
	 * Authorization: Bearer 4/CKN69L8gdSYp5_pwH3XlFQZ3ndFhkXf9P2_TiHRG-bA
	 * {
	 * "credentialID": "GX0112348",
	 * "SAD": "_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
	 * "hash":
	 * [
	 * "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
	 * "c1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0="
	 * ],
	 * "hashAlgo": "2.16.840.1.101.3.4.2.1",
	 * signAlgo": "1.2.840.113549.1.1.1",
	 * "clientData": "12345678"
	 * }
	 *
	 *
	 * Example response:
	 *
	 * HTTP/1.1 200 OK
	 * Content-Type: application/json;charset=UTF-8
	 * {
	 * "signatures":
	 * [
	 * "KedJuTob5gtvYx9qM3k3gm7kbLBwVbEQRl26S2tmXjqNND7MRGtoew==",
	 * "Idhef7xzgtvYx9qM3k3gm7kbLBwVbE98239S2tm8hUh85KKsfdowel=="
	 * ]
	 * }
	 */
	@PostMapping("signHash")
	@ResponseStatus(HttpStatus.OK)
	public CSCSignaturesSignHashResponse signHash(
			@CurrentUser UserPrincipal userPrincipal,
			@Valid @RequestBody CSCSignaturesSignHashRequest signHashRequest) {

		return signaturesService.signHash(userPrincipal, signHashRequest);
	}
}
