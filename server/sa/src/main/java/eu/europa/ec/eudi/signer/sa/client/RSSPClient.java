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

package eu.europa.ec.eudi.signer.sa.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import eu.europa.ec.eudi.signer.common.AccessCredentialDeniedException;
import eu.europa.ec.eudi.signer.common.FailedConnectionVerifier;
import eu.europa.ec.eudi.signer.common.TimeoutException;
import eu.europa.ec.eudi.signer.csc.payload.*;
import eu.europa.ec.eudi.signer.sa.config.RSSPClientConfig;
import eu.europa.ec.eudi.signer.sa.error.CredentialNotFoundException;
import eu.europa.ec.eudi.signer.sa.error.InvalidRequestException;
import eu.europa.ec.eudi.signer.sa.error.RSSPClientException;

import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * REST client for the RSSP web service, used by signing applications to get
 * credentials and sign hashes
 */
public class RSSPClient implements SignerClient {
    private final RSSPClientConfig config;
    private final WebClient webClient;
    private ClientContext context;
    private static final Logger log = LoggerFactory.getLogger(RSSPClient.class);

    public RSSPClient(RSSPClientConfig config) {
        this.config = config;
        webClient = WebClient.builder().baseUrl(config.getCscBaseUrl()).defaultCookie("cookieKey", "cookieValue")
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).build();
    }

    @Override
    public RedirectLinkResponse getOIDRedirectLink(String redirect_uri) {
        final RedirectLinkResponse response = requestOIDRedirectLink(redirect_uri).block();
        assert response != null;
        return response;
    }

    @Override
    public ClientContext prepCredential() {
        final List<CredentialInfo> credentials = listCredentialsForCurrentUser();
        if (credentials == null || credentials.isEmpty()) {
            throw new CredentialNotFoundException("The current user has no credentials with which to sign");
        }

        List<String> credentialIDs = credentials.stream().map(CredentialInfo::getAlias).collect(Collectors.toList());

        // alias
        String credentialID = getContext().getCredentialID();
        if (StringUtils.hasText(credentialID)) {
            if (!credentialIDs.contains(credentialID)) {
                throw new InvalidRequestException("The current user does not own the specified credential");
            }
        } else {
            credentialID = credentialIDs.get(0);
        }
        context.setCredentialID(credentialID);

        final CSCCredentialsInfoResponse credentialInfo = getCredentialInfo(credentialID);
        if (credentialInfo == null) {
            throw new InvalidRequestException("Could not get info on the specified credential");
        }

        // get the algo from the credential info
        final CSCCredentialsInfoResponse.Key key = credentialInfo.getKey();
        if (key == null) {
            throw new InvalidRequestException("Could not get key info for the credential");
        }
        final List<String> algos = key.getAlgo();
        if (algos == null || algos.isEmpty()) {
            throw new InvalidRequestException("Could not get sign algos from the key info for the credential");
        }
        // simply use the fisrt algo
        String signAlgo = algos.get(0);
        context.setSignAlgo(signAlgo);

        final CSCCredentialsInfoResponse.Cert cert = credentialInfo.getCert();
        context.setSubject(cert.getSubjectDN());
        return context;
    }

    @Override
    public byte[] signHash(String pdfName, byte[] pdfHash, String responseCode, ClientContext context)
            throws FailedConnectionVerifier, TimeoutException, AccessCredentialDeniedException, Exception {

        String credentialAlias = context.getCredentialID();

        // now authorize it
        String SAD = authorizeCredential(credentialAlias, responseCode);
        if (SAD == null) {
            throw new InvalidRequestException("Could not authorize the credential with the PIN");
        }

        // and use it to sign
        log.info("Signing hash with credential: {}", credentialAlias);
        final String pdfHashB64 = Base64.getEncoder().encodeToString(pdfHash);
        final String signedHashB64 = signHash(pdfName, pdfHashB64, credentialAlias, SAD, context.getSignAlgo());
        return Base64.getDecoder().decode(signedHashB64);
    }

    // -------

    public Mono<RedirectLinkResponse> requestOIDRedirectLink(String redirect_uri) {
        return webClient.get()
                .uri("/credentials/authorizationLink?redirect_uri="+redirect_uri)
                .header("Authorization", buildAuthHeader())
                .retrieve()
                .bodyToMono(
                        RedirectLinkResponse.class);
    }

    public Mono<CredentialInfo[]> requestCredentialList(CSCCredentialsListRequest request) {
        String apiBaseUrl = this.config.getApiBaseUrl();
        WebClient aux = WebClient.builder().baseUrl(apiBaseUrl)
                .defaultCookie("cookieKey", "cookieValue")
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).build();

        return aux.post()
                .uri("/credentials/list")
                .header("Authorization", buildAuthHeader())
                .exchangeToMono(response -> {
                    if (response.statusCode().equals(HttpStatus.OK)) {
                        return response.bodyToMono(CredentialInfo[].class).log();
                    } else {
                        return Mono.error(new RSSPClientException(response));
                    }
                });
    }

    public Mono<CSCCredentialsInfoResponse> requestCredentialInfo(CSCCredentialsInfoRequest request) {
        return webClient.post()
                .uri("/credentials/info")
                .bodyValue(request)
                .header("Authorization", buildAuthHeader())
                .exchangeToMono(response -> {
                    if (response.statusCode().equals(HttpStatus.OK)) {
                        return response.bodyToMono(CSCCredentialsInfoResponse.class);
                    } else {
                        return Mono.error(new RSSPClientException(response));
                    }
                });
    }

    public Mono<CSCSignaturesSignHashResponse> requestSignHash(CSCSignaturesSignHashRequest request) {
        return webClient.post()
                .uri("/signatures/signHash")
                .bodyValue(request)
                .header("Authorization", buildAuthHeader())
                .exchangeToMono(response -> {
                    if (response.statusCode().equals(HttpStatus.OK)) {
                        return response.bodyToMono(CSCSignaturesSignHashResponse.class);
                    } else {
                        return Mono.error(new RSSPClientException(response));
                    }
                });
    }

    // lista de aliases
    public List<CredentialInfo> listCredentialsForCurrentUser() {
        CSCCredentialsListRequest request = new CSCCredentialsListRequest();
        final CredentialInfo[] response = requestCredentialList(request).block();
        return Arrays.stream(response).collect(Collectors.toList());
    }

    public CSCCredentialsInfoResponse getCredentialInfo(String credentialAlias) {
        CSCCredentialsInfoRequest request = new CSCCredentialsInfoRequest();
        request.setCredentialID(credentialAlias);
        request.setCertInfo(true);
        return requestCredentialInfo(request).block();
    }

    public String authorizeCredential(String credentialAlias, String responseCode) throws FailedConnectionVerifier, TimeoutException, AccessCredentialDeniedException, Exception {
        CSCCredentialsAuthorizeRequest request = new CSCCredentialsAuthorizeRequest();
        request.setCredentialID(credentialAlias);
        request.setNumSignatures(1);
        request.setCode(responseCode);

        try {
            Mono<CSCCredentialsAuthorizeResponse> authorizationResponse = webClient.post()
                    .uri("/credentials/authorize")
                    .bodyValue(request)
                    .header("Authorization", buildAuthHeader())
                    .exchangeToMono(response -> {
                        if (response.statusCode().equals(HttpStatus.OK)) {
                            return response.bodyToMono(CSCCredentialsAuthorizeResponse.class);
                        } else if (response.statusCode().equals(HttpStatus.NOT_FOUND)) {
                            return Mono.error(new FailedConnectionVerifier());
                        } else if (response.statusCode().equals(HttpStatus.GATEWAY_TIMEOUT)) {
                            return Mono.error(new TimeoutException());
                        } else if (response.statusCode().equals(HttpStatus.UNAUTHORIZED)) {
                            return Mono.error(new AccessCredentialDeniedException());
                        } else {
                            return Mono.error(new Exception("The access to the Credentials was not authorized."));
                        }
                    });

            return authorizationResponse
                    .map(CSCCredentialsAuthorizeResponse::getSAD)
                    .onErrorMap(error -> error)
                    .block();
        } catch (Throwable e) {
            if (e.getCause().getClass().equals(FailedConnectionVerifier.class)) {
                log.error("FailedConnectionVerifier");
                throw new FailedConnectionVerifier();

            } else if (e.getCause().getClass().equals(TimeoutException.class)) {
                log.error("TimeoutException");
                throw new TimeoutException();

            } else if (e.getCause().getClass().equals(AccessCredentialDeniedException.class)) {
                log.error("AccessCredentialDeniedException");
                throw new AccessCredentialDeniedException();

            } else {
                log.error("Other");
                throw new Exception("The access to the Credentials was not authorized.");
            }
        }
    }

    public String signHash(String pdfName, String pdfHash, String credentialAlias, String SAD, String signAlgo) {
        CSCSignaturesSignHashRequest request = new CSCSignaturesSignHashRequest();
        request.setHash(Collections.singletonList(pdfHash));
        request.setCredentialID(credentialAlias);
        request.setSAD(SAD);
        request.setSignAlgo(signAlgo);
        request.setClientData(pdfName);
        final CSCSignaturesSignHashResponse response = requestSignHash(request).block();
        assert response != null;
        final List<String> signatures = response.getSignatures();
        return signatures.get(0);
    }

    /**
     * Set the context to be used in the next request
     */
    public void setContext(ClientContext context) {
        this.context = context;
    }

    private ClientContext getContext() {
        if (context == null) {
            throw new InvalidRequestException("ClientContext not set before using client");
        }
        return context;
    }

    private String buildAuthHeader() {
        String authorizationHeader = getContext().getAuthorizationHeader();
        if (authorizationHeader == null) {
            throw new InvalidRequestException("Authorization not set in context");
        }
        return authorizationHeader;
    }
}
