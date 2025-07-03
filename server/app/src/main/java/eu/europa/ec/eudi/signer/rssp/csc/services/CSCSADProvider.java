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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import eu.europa.ec.eudi.signer.csc.error.CSCInvalidRequest;
import eu.europa.ec.eudi.signer.rssp.common.config.CSCProperties;
import eu.europa.ec.eudi.signer.rssp.common.config.SADProperties;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.security.jwt.JwtProvider;
import eu.europa.ec.eudi.signer.rssp.security.jwt.JwtToken;

@Service
public class CSCSADProvider {
    private static final Logger log = LoggerFactory.getLogger(CSCSADProvider.class);
    private final JwtProvider jwtProvider;
    private final long lifetimeSeconds;

    public CSCSADProvider(CSCProperties cscProperties, SADProperties sadProperties) {
		jwtProvider = new JwtProvider(sadProperties);
        lifetimeSeconds = sadProperties.getLifetimeMinutes() * 60;
    }

    public String createSAD(String credentialId) {
        final JwtToken token = jwtProvider.createToken(credentialId);
        return token.getRawToken();
    }

    public long getLifetimeSeconds() {
        return lifetimeSeconds;
    }

    public void validateSAD(String rawSAD) throws ApiException {
        JwtToken token = jwtProvider.validateToken(rawSAD);
        if (!token.isValid()) {
            log.error("Invalid SAD provided: {}", token.getError());
        }
        if (token.isExpired()) {
            // SAD expired - return the proper CSC error per 11.9 of the spec
            throw new ApiException(CSCInvalidRequest.SADExpired);
        } else if (!token.isValid()) {
            throw new ApiException(CSCInvalidRequest.InvalidSAD);
        }
    }
}
