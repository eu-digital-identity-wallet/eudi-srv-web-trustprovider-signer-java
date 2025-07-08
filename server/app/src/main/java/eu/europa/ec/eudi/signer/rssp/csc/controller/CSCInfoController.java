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
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.ec.eudi.signer.csc.model.CSCConstants;
import eu.europa.ec.eudi.signer.csc.payload.CSCInfoRequest;
import eu.europa.ec.eudi.signer.csc.payload.CSCInfoResponse;
import eu.europa.ec.eudi.signer.rssp.csc.services.CSCInfoService;

/**
 * INFO endpoint from:
 * From section 11.1 of the CSC API V_1.0.4.0 spec
 */
@RestController
@RequestMapping(value = "/info")
public class CSCInfoController {

	private static final Logger log = LoggerFactory.getLogger(CSCInfoController.class);
	private CSCInfoService infoService;

	@Autowired
	public CSCInfoController(CSCInfoService infoService) {
		this.infoService = infoService;
	}

	/**
	 * Example request:
	 * POST /csc/v1/info HTTP/1.1 Host: service.domain.org Content-Type:
	 * application/json
	 * {}
	 *
	 * Example response:
	 * HTTP/1.1 200 OK
	 * Content-Type: application/json;charset=UTF-8
	 * {
	 * "specs": "1.0.3.0",
	 * "name": "ACME Trust Services",
	 * "logo": "https://service.domain.org/images/logo.png",
	 * "region": "IT",
	 * "lang": "en-US",
	 * "description": "An efficient remote signature service",
	 * "authType": ["basic", "oauth2code"],
	 * "oauth2": "https://www.domain.org/",
	 * "methods": ["auth/login", "auth/revoke", "credentials/list",
	 * "credentials/info",
	 * "credentials/authorize",
	 * "credentials/sendOTP",
	 * "signatures/signHash"]
	 * }
	 *
	 * @param infoRequest
	 */
	@PostMapping("")
	@ResponseStatus(HttpStatus.OK)
	public CSCInfoResponse info(@RequestBody(required = false) CSCInfoRequest infoRequest) {
		if (infoRequest != null) {
			// we ignore lang but log it if its different from ours
			String lang = infoRequest.getLang();
			if (StringUtils.hasText(lang)) {
				if (!lang.equals(CSCConstants.CSC_LANG)) {
					log.warn("Unsupported lang in request: {}. Trust Provider Signer only supports {}", lang,
							CSCConstants.CSC_LANG);
				}
			}
		}

		CSCInfoResponse info = new CSCInfoResponse(infoService.getInfo());
		return info;
	}
}
