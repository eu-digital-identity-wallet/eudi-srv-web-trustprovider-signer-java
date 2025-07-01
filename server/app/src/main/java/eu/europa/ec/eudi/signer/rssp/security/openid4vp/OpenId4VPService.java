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

package eu.europa.ec.eudi.signer.rssp.security.openid4vp;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.Optional;
import java.util.Map.Entry;

import eu.europa.ec.eudi.signer.rssp.common.config.JwtConfigProperties;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;
import eu.europa.ec.eudi.signer.rssp.security.jwt.JwtProvider;
import eu.europa.ec.eudi.signer.rssp.security.jwt.JwtToken;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.rssp.api.model.RoleName;
import eu.europa.ec.eudi.signer.rssp.api.payload.AuthResponse;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.common.error.VPTokenInvalid;
import eu.europa.ec.eudi.signer.rssp.common.error.VerifiablePresentationVerificationException;
import eu.europa.ec.eudi.signer.rssp.ejbca.EJBCAService;
import eu.europa.ec.eudi.signer.rssp.entities.User;
import eu.europa.ec.eudi.signer.rssp.repository.UserRepository;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.issuersigned.IssuerSignedItem;

@Service
public class OpenId4VPService {

    private static final Logger log = LoggerFactory.getLogger(OpenId4VPService.class);

    private final UserRepository repository;
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;
    private final EJBCAService ejbcaService;
    private final LoggerUtil loggerUtil;

    @Autowired
    public OpenId4VPService(UserRepository repository, AuthenticationManager authenticationManager,
                            JwtConfigProperties jwtConfigProperties, EJBCAService ejbcaService, LoggerUtil loggerUtil) {
        this.repository = repository;
        this.authenticationManager = authenticationManager;
        this.jwtProvider = new JwtProvider(jwtConfigProperties);
        this.ejbcaService = ejbcaService;
        this.loggerUtil = loggerUtil;
    }

    public record UserOIDTemporaryInfo(User user, String givenName, String familyName) {

        public String getFullName() {
                return givenName + " " + familyName;
            }
        }

    /**
     * Function that allows to load the user from the response of the verifier (VP
     * Token) and add it to the database.
     * Additionally, it generates the JwtToken for the user authentication
     * 
     * @param messageFromVerifier                      the message receive from the
     *                                                 verifier
     * @return the Jwt Token created
     * @throws VerifiablePresentationVerificationException the error that could be
     *                                                     obtained from the vp
     *                                                     validation
     * @throws VPTokenInvalid                              the exception that could
     *                                                     appear in the additional
     *                                                     validation of the vp
     *                                                     token
     */
    public AuthResponse loadUserFromVerifierResponseAndGetJWTToken(String messageFromVerifier)
            throws VerifiablePresentationVerificationException, VPTokenInvalid, NoSuchAlgorithmException, Exception {

        JSONObject vp;
        try{
            vp =  new JSONObject(messageFromVerifier);
        }
        catch (JSONException e){
            throw new Exception("The response from the Verifier doesn't contain a correctly formatted JSON string.");
        }
        VPValidator validator = new VPValidator(vp, VerifierClient.PresentationDefinitionId, VerifierClient.PresentationDefinitionInputDescriptorsId,
                this.ejbcaService);
        Map<Integer, String> logsMap = new HashMap<>();
        MDoc document = validator.loadAndVerifyDocumentForVP(logsMap);
        UserOIDTemporaryInfo user = loadUserFromDocument(document);
        String token = addToDBandCreateJWTToken(user.user(), user.givenName(), user.familyName(), logsMap);
        return new AuthResponse(token);
    }

    /**
     * Function that allows to load the user from the response of the verifier (VP
     * Token)
     * 
     * @param messageFromVerifier                      the message received from the
     *                                                 verifier
     * @param ejbcaService                             the EJBCA Service
     * @param logsMap                                  an hash map to load the logs
     *                                                 from the validator
     * @return the user loaded
     */
    public User loadUserFromVerifierResponse(String messageFromVerifier, EJBCAService ejbcaService, Map<Integer, String> logsMap)
            throws VerifiablePresentationVerificationException, VPTokenInvalid, NoSuchAlgorithmException, Exception {

        JSONObject responseVerifier;
        try{
            responseVerifier =  new JSONObject(messageFromVerifier);
        }
        catch (JSONException e){
            throw new Exception("The response from the Verifier doesn't contain a correctly formatted JSON string.");
        }

        VPValidator validator = new VPValidator(responseVerifier, VerifierClient.PresentationDefinitionId,
                VerifierClient.PresentationDefinitionInputDescriptorsId, ejbcaService);
        MDoc document = validator.loadAndVerifyDocumentForVP(logsMap);
        return loadUserFromDocument(document).user();
    }

    public UserOIDTemporaryInfo loadUserFromDocument(MDoc document) throws VPTokenInvalid, NoSuchAlgorithmException {
        List<IssuerSignedItem> l = document.getIssuerSignedItems(document.getDocType().getValue());

        String familyName = null;
        String givenName = null;
        String birthDate = null;
        String issuingCountry = null;
        String issuanceAuthority = null;
        // boolean ageOver18 = false;

        for (IssuerSignedItem el : l) {
            switch (el.getElementIdentifier().getValue()) {
                case "family_name" -> familyName = el.getElementValue().getValue().toString();
                case "given_name" -> givenName = el.getElementValue().getValue().toString();
                case "birth_date" -> birthDate = el.getElementValue().getValue().toString();
                // case "age_over_18" -> ageOver18 = (boolean) el.getElementValue().getValue();
                case "issuing_authority" -> issuanceAuthority = el.getElementValue().getValue().toString();
                case "issuing_country" -> issuingCountry = el.getElementValue().getValue().toString();
            }
        }

        if (familyName == null || givenName == null || birthDate == null || issuingCountry == null) {
            String logMessage = SignerError.VPTokenMissingValues.getCode()
                    + "(loadUserFromDocument in OpenId4VPService.class): "
                    + SignerError.VPTokenMissingValues.getDescription();
            log.error(logMessage);
            throw new VPTokenInvalid(SignerError.VPTokenMissingValues,
                    "The VP token doesn't have all the required values.");
        }

        User user = new User(familyName, givenName, birthDate, issuingCountry, issuanceAuthority,
                RoleName.ROLE_USER.name());
        return new UserOIDTemporaryInfo(user, givenName, familyName);
    }

    private String addToDBandCreateJWTToken(User userFromVerifierResponse, String givenName, String surname,
            Map<Integer, String> logsMap) {
        Optional<User> userInDatabase = repository.findByHash(userFromVerifierResponse.getHash());
        if (userInDatabase.isEmpty()) {
            repository.save(userFromVerifierResponse);
        }

        Authentication authentication = authenticationManager.authenticate(new OpenId4VPAuthenticationToken(userFromVerifierResponse.getHash(), givenName, surname));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        if (userInDatabase.isEmpty()) {
            for (Entry<Integer, String> l : logsMap.entrySet())
                loggerUtil.logsUser(1, userFromVerifierResponse.getId(), l.getKey(), l.getValue());

            LoggerUtil.desc = "PID HASH: " + userFromVerifierResponse.getHash();
            loggerUtil.logsUser(1, userFromVerifierResponse.getId(), 4, LoggerUtil.desc);
        } else {
            User u = userInDatabase.get();

            for (Entry<Integer, String> l : logsMap.entrySet())
                loggerUtil.logsUser(1, u.getId(), l.getKey(), l.getValue());

            LoggerUtil.desc = "PID HASH: " + u.getHash();
            loggerUtil.logsUser(1, u.getId(), 4, LoggerUtil.desc);
        }
        return createToken(authentication);
    }

    public String createToken(Authentication authentication) {
        try {
            if (authentication.getClass().equals(OpenId4VPAuthenticationToken.class)) {
                UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
                String username = userPrincipal.getUsername();
                String givenName = userPrincipal.getGivenName();
                String surname = userPrincipal.getSurname();
                final JwtToken token = jwtProvider.createToken(username + ";" + givenName + ";" + surname);
                return token.getRawToken();
            } else {
                UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
                String subject = userPrincipal.getUsername();
                final JwtToken token = jwtProvider.createToken(subject);
                return token.getRawToken();
            }
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }
}
