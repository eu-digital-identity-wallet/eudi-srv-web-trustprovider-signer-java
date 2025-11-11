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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import eu.europa.ec.eudi.signer.common.FailedConnectionVerifier;
import eu.europa.ec.eudi.signer.common.TimeoutException;
import eu.europa.ec.eudi.signer.csc.payload.RedirectLinkResponse;
import eu.europa.ec.eudi.signer.rssp.common.config.VerifierProperties;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.util.WebUtils;

/**
 * Component responsible to make requests to an OpenID4VP Verifier
 * And create the links necessary to redirect the user to the Verifier
 */
@Component
public class VerifierClient {
    public static String Authentication = "Authentication";
    public static String Authorization = "Authorization";
    public static String PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID = "eu.europa.ec.eudi.pid.1";

    private static final Logger log = LoggerFactory.getLogger(VerifierClient.class);
    private final VerifierProperties verifierProperties;
    private final VerifierCreatedVariables verifierVariables;

    public VerifierClient(VerifierProperties verifierProperties) {
        this.verifierProperties = verifierProperties;
        this.verifierVariables = new VerifierCreatedVariables();
    }

    /**
     * Function that allows to make a Presentation Request, following the OpenID for
     * Verifiable Presentations - draft 20, to the verifier
     * This function already writes the logs for the ApiException. The message in
     * that exceptions can also be used to display info to the user.
     * 
     * @param user an identifier of the user that made the request (ex: a cookie or
     *             an id)
     * @param type the type of the operation that requires the use of OID4VP (ex:
     *             authentication or authorization)
     * @return the deep link that redirects the user to the EUDI Wallet
     */
    public RedirectLinkResponse initPresentationTransaction(String user, String type, String redirect_uri) throws Exception {
        log.info("Starting Init Transaction Request.");
        if (operationTypeIsInvalid(type)) {
            log.error("The 'initPresentationTransaction' type ({}) is not supported.", type);
            log.error(SignerError.UnexpectedOperationType.getFormattedMessage());
            throw new ApiException(SignerError.UnexpectedOperationType, SignerError.UnexpectedOperationType.getFormattedMessage());
        }

        String nonce = generateNonce();
        log.info("Generated nonce.");

        RedirectLinkResponse response = new RedirectLinkResponse();

        // Send HTTP Post Request & Receives the Response
        JSONObject responseInitTransactionCrossDevice;
        JSONObject responseInitTransactionSameDevice;
        try {
            responseInitTransactionCrossDevice = httpRequestToInitPresentation(user, nonce, true, "");
            log.info("Redirect URI: {}", redirect_uri);
            responseInitTransactionSameDevice = httpRequestToInitPresentation(user, nonce, false, redirect_uri);
            log.info("Successfully posted the InitTransaction to the OID4VP Verifier.");
        } catch (Exception e) {
            log.error(SignerError.FailedConnectionToVerifier.getFormattedMessage());
            throw new ApiException(SignerError.FailedConnectionToVerifier, SignerError.FailedConnectionToVerifier.getFormattedMessage());
        }

        String presentation_id_cross = getPresentationIdAndCreateDeepLink(responseInitTransactionCrossDevice, response, true);
        verifierVariables.addUsersVerifierCreatedVariable(user, "cross", type, nonce, presentation_id_cross);
        log.info("User {}-{} executed successfully the operation {}. Nonce: {} & Presentation_id: {}", user, "cross", type, nonce, presentation_id_cross);

        String presentation_id_same = getPresentationIdAndCreateDeepLink(responseInitTransactionSameDevice, response, false);
        verifierVariables.addUsersVerifierCreatedVariable(user, "same", type, nonce, presentation_id_same);
		log.info("User {}-{} executed successfully the operation {}. Nonce: {} & Presentation_id: {}", user, "same", type, nonce, presentation_id_same);
        return response;
    }

    private boolean operationTypeIsInvalid(String type) {
        return !Objects.equals(type, Authorization) && !Objects.equals(type, Authentication);
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        return headers;
    }

    private String generateNonce() throws Exception {
        SecureRandom prng = new SecureRandom();
        String randomNum = String.valueOf(prng.nextInt());
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(randomNum.getBytes());
        return Base64.getUrlEncoder().encodeToString(result);
    }

    private JSONObject getDCQLQueryJSON(){
        String dcqlQuery = "{" +
              "'credentials': [" +
              "{" +
              "'id': 'query_0'," +
              "'format': 'mso_mdoc'," +
              "'meta': {'doctype_value': '"+PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"'}," +
              "'claims': [" +
              "{" +
              "'path': ['" + PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"', 'family_name']," +
              "'intent_to_retain': false" +
              "}," +
              "{" +
              "'path': ['" + PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"', 'given_name']," +
              "'intent_to_retain': false" +
              "}," +
              "{" +
              "'path': ['" + PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"', 'birth_date']," +
              "'intent_to_retain': false" +
              "}," +
              "{" +
              "'path': ['" + PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"', 'issuing_authority']," +
              "'intent_to_retain': false" +
              "}," +
              "{" +
              "'path': ['" + PRESENTATION_DEFINITION_INPUT_DESCRIPTORS_ID+"', 'issuing_country']," +
              "'intent_to_retain': false" +
              "}" +
              "]" +
              "}" +
              "]" +
              "}";
        return new JSONObject(dcqlQuery);
    }

    private String getInitTransactionCrossDeviceBody(String nonce) {
        JSONObject dcqlQueryJSON = getDCQLQueryJSON();

        JSONObject jsonBodyToInitPresentation = new JSONObject();
        jsonBodyToInitPresentation.put("type", "vp_token");
        jsonBodyToInitPresentation.put("nonce", nonce);
        jsonBodyToInitPresentation.put("dcql_query", dcqlQueryJSON);
        return jsonBodyToInitPresentation.toString();
    }

    private String getInitTransactionSameDeviceBody(String user, String nonce, String redirect_uri) {
        JSONObject dcqlQueryJSON = getDCQLQueryJSON();

        String redirectUri = redirect_uri+"?session_id="+user+"&response_code={RESPONSE_CODE}";

        JSONObject jsonBodyToInitPresentation = new JSONObject();
        jsonBodyToInitPresentation.put("type", "vp_token");
        jsonBodyToInitPresentation.put("nonce", nonce);
        jsonBodyToInitPresentation.put("dcql_query", dcqlQueryJSON);
        jsonBodyToInitPresentation.put("wallet_response_redirect_uri_template", redirectUri);
        return jsonBodyToInitPresentation.toString();
    }

    private JSONObject httpRequestToInitPresentation(String user, String nonce, boolean crossDevice, String redirect_uri) throws Exception {
        Map<String, String> headers = getHeaders();
        String presentationDefinition;
        if(crossDevice)
            presentationDefinition = getInitTransactionCrossDeviceBody(nonce);
        else
            presentationDefinition = getInitTransactionSameDeviceBody(user, nonce, redirect_uri);

        HttpResponse response;
        log.info("Making request to Verifier: {}", presentationDefinition);
        try {
            response = WebUtils.httpPostRequest(verifierProperties.getUrl(), headers, presentationDefinition);
        } catch (Exception e) {
            log.error("An error occurred when trying to connect to the Verifier. {}", e.getMessage());
            throw new Exception("An error occurred when trying to connect to the Verifier");
        }

        if (response.getStatusLine().getStatusCode() != 200) {
            String error = WebUtils.convertStreamToString(response.getEntity().getContent());
            int statusCode = response.getStatusLine().getStatusCode();
			log.error("HTTP Post Request not successful. Error : {}", statusCode);
			log.error("Error: {}", error);
            throw new Exception("HTTP Post Request not successful. Error : " + response.getStatusLine().getStatusCode());
        }

        HttpEntity entity = response.getEntity();
        if (entity == null) {
            log.error("Http Post response from the presentation request is empty.");
            throw new Exception("Response to the presentation request is empty.");
        }

        String result = WebUtils.convertStreamToString(entity.getContent());
        JSONObject responseVerifier;
        try{
            responseVerifier =  new JSONObject(result);
        }
        catch (JSONException e){
            log.error("The response of the presentation request from the Verifier doesn't contain a correctly formatted JSON string.");
            throw new Exception("The response from the Verifier doesn't contain a correctly formatted JSON string.");
        }
        return responseVerifier;
    }

    private String getPresentationIdAndCreateDeepLink(JSONObject responseFromVerifier, RedirectLinkResponse response, boolean crossDevice) {
        Set<String> keys = responseFromVerifier.keySet();

        if (!keys.contains("request_uri")){
            log.error("Missing 'request_uri' from InitTransaction Response");
            log.error(SignerError.MissingDataInResponseVerifier.getFormattedMessage());
            throw new ApiException(SignerError.MissingDataInResponseVerifier, SignerError.MissingDataInResponseVerifier.getFormattedMessage());
        }
        if(!keys.contains("client_id")){
            log.error("Missing 'client_id' from InitTransaction Response");
            log.error(SignerError.MissingDataInResponseVerifier.getFormattedMessage());
            throw new ApiException(SignerError.MissingDataInResponseVerifier, SignerError.MissingDataInResponseVerifier.getFormattedMessage());
        }
        if(!keys.contains("transaction_id")){
            log.error("Missing 'transaction_id' from InitTransaction Response");
            log.error(SignerError.MissingDataInResponseVerifier.getFormattedMessage());
            throw new ApiException(SignerError.MissingDataInResponseVerifier, SignerError.MissingDataInResponseVerifier.getFormattedMessage());
        }

        String request_uri = responseFromVerifier.getString("request_uri");
		log.info("Request URI: {}", request_uri);
        String client_id = responseFromVerifier.getString("client_id");
		log.info("Client Id: {}", client_id);
        /*if(!client_id.contains(this.verifierProperties.getClientId())){
            log.error(SignerError.UnexpectedError.getFormattedMessage());
            throw new ApiException(SignerError.UnexpectedError, SignerError.UnexpectedError.getFormattedMessage());
        }*/
        String presentation_id = responseFromVerifier.getString("transaction_id");
		log.info("Transaction Id: {}", presentation_id);
        String encoded_request_uri = URLEncoder.encode(request_uri, StandardCharsets.UTF_8);

        String deepLink = redirectUriDeepLink(encoded_request_uri, client_id);
        if(crossDevice)
            response.setCross_device_link(deepLink);
        else
            response.setSame_device_link(deepLink);
        return presentation_id;
    }

    private String redirectUriDeepLink(String request_uri, String client_id) {
        return "eudi-openid4vp://" + verifierProperties.getAddress() + "?client_id=" + client_id + "&request_uri=" + request_uri;
    }

    /**
     * Function that allows to get the VP Token from the Verifier.
     * This function realizes an active waiting
     *
     * @param user an identifier of the user that made the request (ex: a cookie or
     *             an id)
     * @param type the type of the operation that requires the use of OID4VP (ex:
     *             authentication or authorization)
     * @return the VP Token received from the Verifier
     */
    public String getVPTokenFromVerifierRecursive(String user, String type) throws Exception {
        if (operationTypeIsInvalid(type)) {
            log.error(SignerError.UnexpectedOperationType.getFormattedMessage());
            throw new ApiException(SignerError.UnexpectedOperationType, SignerError.UnexpectedOperationType.getFormattedMessage());
        }

        VerifierCreatedVariable variables = verifierVariables.getUsersVerifierCreatedVariable(user, "cross", type);
        if (variables == null) {
			log.error("{} Variables required to receive answer from the Verifier were not found.", SignerError.UnexpectedError.getCode());
            throw new ApiException(SignerError.UnexpectedError, SignerError.UnexpectedError.getFormattedMessage());
        }
        String nonce = variables.getNonce();
        String presentation_id = variables.getPresentation_id();
		log.info("Current Verifier Variables State: {}", verifierVariables);
        log.info("User {}-{} tried executed the operation {}. Nonce: {} & Presentation_id: {}", user, "cross", type, nonce, presentation_id);

        Map<String, String> headers = getHeaders();
        String url = uriToRequestWalletPID(presentation_id, nonce);

        String message = null;
        int responseCode = 400;
        long startTime = System.currentTimeMillis();
        while (responseCode != 200 && (System.currentTimeMillis() - startTime) < 60000) {
            WebUtils.StatusAndMessage response;
            try {
                response = WebUtils.httpGetRequests(url, headers);
            } catch (Exception e) {
                log.error(SignerError.FailedConnectionToVerifier.getFormattedMessage());
                throw new ApiException(SignerError.FailedConnectionToVerifier, SignerError.FailedConnectionToVerifier.getFormattedMessage());
            }

            if (response.getStatusCode() == 404)
                throw new FailedConnectionVerifier();
            else if (response.getStatusCode() == 200) {
                responseCode = 200;
                message = response.getMessage();
            } else
                TimeUnit.SECONDS.sleep(1);
        }
        if (responseCode == 400 && (System.currentTimeMillis() - startTime) >= 60000)
            throw new TimeoutException();

        if(message == null || Objects.equals(message, "")){
            String errorMessage = "It was not possible to retrieve a VP Token from the OID4VP Verifier Backend.";
            log.error("{} The message retrieved from the OID4VP Verifier Backend is empty.", errorMessage);
            throw new ApiException(SignerError.MissingDataInResponseVerifier, "The server expected to receive a well-formatted VP Token from the OID4VP Verifier Backend. However, the response from the OID4VP Verifier Backend is empty.");
        }
        log.info("Retrieved the VP Token from the Verifier to authenticate the user.");

        // If successfully retrieves a response from the cross device, it can delete the variables from the same device:
        verifierVariables.removeUsersVerifierCreatedVariable(user, "same", type);
        return message;
    }

    public String getVPTokenFromVerifier(String user, String type, String code) {
        if (operationTypeIsInvalid(type)) {
            log.error(SignerError.UnexpectedOperationType.getFormattedMessage());
            throw new ApiException(SignerError.UnexpectedOperationType, SignerError.UnexpectedOperationType.getFormattedMessage());
        }
        VerifierCreatedVariable variables = verifierVariables.getUsersVerifierCreatedVariable(user, "same", type);
        if (variables == null) {
            log.error("Failed to retrieve the required local variables to complete the authentication.");
            throw new ApiException(SignerError.UnexpectedError, SignerError.UnexpectedError.getFormattedMessage());
        }
        log.info("Retrieved the required local variables to complete the authentication.");
        log.debug("User: {}-{} & Nonce: {} & Presentation_id: {}", user, "same", variables.getNonce(), variables.getPresentation_id());

        Map<String, String> headers = getHeaders();
        String url = getUrlToRetrieveVPTokenWithResponseCode(variables.getPresentation_id(), variables.getNonce(), code);
        log.info("Obtained the link to retrieve the VP Token from the Verifier.");
        log.debug("Link to retrieve the VP Token: {}", url);

        WebUtils.StatusAndMessage response;
        try {
            response = WebUtils.httpGetRequests(url, headers);
        } catch (Exception e) {
            log.error("Failed to retrieve the VP Token from the Verifier. Error: {}", e.getMessage());
            throw new ApiException(SignerError.FailedConnectionToVerifier, SignerError.FailedConnectionToVerifier.getFormattedMessage());
        }

        if(response.getStatusCode() == 200){
            if(response.getMessage() == null || Objects.equals(response.getMessage(), "")){
                String errorMessage = "It was not possible to retrieve a VP Token from the OID4VP Verifier Backend.";
                log.error("{} The message retrieved from the OID4VP Verifier Backend is empty.", errorMessage);
                throw new ApiException(SignerError.MissingDataInResponseVerifier, "The server expected to receive a well-formatted VP Token from the OID4VP Verifier Backend. However, the response from the OID4VP Verifier Backend is empty.");
            }
            log.info("Retrieved the VP Token from the Verifier to authenticate the user {}.", user);

            verifierVariables.removeUsersVerifierCreatedVariable(user, "cross", type);
            return response.getMessage();
        }
        else{
            log.error("Failed to connect with Verifier and retrieve the VP Token. Status Code: {}. Error: {}", response.getStatusCode(), response.getMessage());
            throw new ApiException(SignerError.FailedConnectionToVerifier, "The OID4VP Verifier service is currently unavailable.");
        }
    }

    private String uriToRequestWalletPID(String presentation_id, String nonce) {
        return verifierProperties.getUrl() + "/" + presentation_id + "?nonce=" + nonce;
    }

    private String getUrlToRetrieveVPTokenWithResponseCode(String presentation_id, String nonce, String code) {
        return verifierProperties.getUrl() + "/" + presentation_id + "?nonce=" + nonce + "&response_code=" + code;
    }
}
