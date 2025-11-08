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

package eu.europa.ec.eudi.signer.rssp.security;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import eu.europa.ec.eudi.signer.common.FailedConnectionVerifier;
import eu.europa.ec.eudi.signer.common.TimeoutException;
import eu.europa.ec.eudi.signer.csc.payload.RedirectLinkResponse;
import eu.europa.ec.eudi.signer.rssp.api.payload.AuthResponse;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.common.error.VPTokenInvalid;
import eu.europa.ec.eudi.signer.rssp.common.error.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.rssp.security.openid4vp.OpenId4VPService;
import eu.europa.ec.eudi.signer.rssp.security.openid4vp.VerifierClient;

@RestController
@RequestMapping("/auth")
public class OpenId4VPController {
    private static final Logger log = LoggerFactory.getLogger(OpenId4VPController.class);
    private final OpenId4VPService service;

    public OpenId4VPController(@Autowired OpenId4VPService service){
        this.service = service;
    }

    @GetMapping("link")
    public ResponseEntity<?> initPresentationTransaction(HttpServletRequest request, HttpServletResponse httpResponse) {
        String redirect_uri = request.getParameter("redirect_uri");
        String redirect_uri_decoded = URLDecoder.decode(redirect_uri, StandardCharsets.UTF_8);
        log.info("redirect_uri from Request: {}", redirect_uri_decoded);

        try {
            Cookie cookie = generateCookie();
            String sessionCookie = cookie.getValue();
            RedirectLinkResponse response = this.service.getRedirectLink(sessionCookie, VerifierClient.Authentication, redirect_uri_decoded);
            ResponseEntity<RedirectLinkResponse> responseEntity = ResponseEntity.ok(response);
            httpResponse.addCookie(cookie);
            return responseEntity;
        } catch (ApiException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            String logMessage = SignerError.UnexpectedError.getCode() + " (initPresentationTransaction in OpenId4VPController.class) " + e.getMessage();
            log.error(logMessage);
            return ResponseEntity.badRequest().body(SignerError.UnexpectedError.getFormattedMessage());
        }
    }

    private Cookie generateCookie() throws NoSuchAlgorithmException {
        SecureRandom prng = new SecureRandom();
        String randomNum = String.valueOf(prng.nextInt());
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(randomNum.getBytes());
        String sessionCookie = Base64.getUrlEncoder().encodeToString(result);
        Cookie cookie = new Cookie("JSESSIONID", sessionCookie);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        return cookie;
    }

    @GetMapping("token/same-device")
    public ResponseEntity<?> waitSameDeviceResponse(HttpServletRequest request) {
        String session_id = request.getParameter("session_id");
        log.info("response_code from Request: {}", session_id);

        String code = request.getParameter("response_code");
        log.info("response_code from Request: {}", code);

        try {
            AuthResponse JWTToken = this.service.getVPTokenFromVerifierAndCreateOID4VPAuthToken(session_id, VerifierClient.Authentication, code);
            return ResponseEntity.ok(JWTToken);
        } catch (FailedConnectionVerifier e) {
            log.error(SignerError.FailedConnectionToVerifier.getFormattedMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(SignerError.FailedConnectionToVerifier.getFormattedMessage());
        } catch (TimeoutException e) {
            log.error(SignerError.ConnectionVerifierTimedOut.getFormattedMessage());
            return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT)
                  .body(SignerError.ConnectionVerifierTimedOut.getFormattedMessage());
        } catch (VerifiablePresentationVerificationException e) {
            String logMessage = "[" + e.getError().getCode() + "] "+ e.getError().getDescription() + ": " + e.getMessage();
            log.error(logMessage);
            return ResponseEntity.badRequest().body(e.getError().getFormattedMessage());
        } catch (VPTokenInvalid e) {
            return ResponseEntity.badRequest().body(e.getError().getFormattedMessage());
        } catch (ApiException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
			log.error("{} {}", SignerError.UnexpectedError.getCode(), e.getMessage());
            return ResponseEntity.badRequest().body(SignerError.UnexpectedError.getFormattedMessage());
        }
    }

    @GetMapping("token")
    public ResponseEntity<?> waitResponse(HttpServletRequest request, @CookieValue("JSESSIONID") String sessionCookie) {
        try {
            AuthResponse JWTToken = this.service.pollVPTokenAndCreateOID4VPAuthToken(sessionCookie, VerifierClient.Authentication);
            return ResponseEntity.ok(JWTToken);
        } catch (FailedConnectionVerifier e) {
            log.error(SignerError.FailedConnectionToVerifier.getFormattedMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(SignerError.FailedConnectionToVerifier.getFormattedMessage());
        } catch (TimeoutException e) {
            log.error(SignerError.ConnectionVerifierTimedOut.getFormattedMessage());
            return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT)
                    .body(SignerError.ConnectionVerifierTimedOut.getFormattedMessage());
        } catch (VerifiablePresentationVerificationException e) {
            String logMessage = e.getError().getCode() + " (waitResponse in OpenId4VPController.class) "
                    + e.getError().getDescription() + ": " + e.getMessage();
            log.error(logMessage);
            return ResponseEntity.badRequest().body(e.getError().getFormattedMessage());
        } catch (VPTokenInvalid e) {
            return ResponseEntity.badRequest().body(e.getError().getFormattedMessage());
        } catch (ApiException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
			log.error("{} {}", SignerError.UnexpectedError.getCode(), e.getMessage());
            return ResponseEntity.badRequest().body(SignerError.UnexpectedError.getFormattedMessage());
        }
    }
}