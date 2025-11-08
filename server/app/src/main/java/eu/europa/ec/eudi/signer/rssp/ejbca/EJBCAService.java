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

package eu.europa.ec.eudi.signer.rssp.ejbca;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import org.json.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import eu.europa.ec.eudi.signer.rssp.util.WebUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;

public class EJBCAService {
    private static final Logger log = LoggerFactory.getLogger(EJBCAService.class);
    private final EJBCAProperties ejbcaProperties;

    public EJBCAService(EJBCAProperties properties) {
        this.ejbcaProperties = properties;
    }

    public String getCertificateAuthorityNameByCountry(String countryCode){
        return this.ejbcaProperties.getCertificateAuthorityName(countryCode);
    }

    // [0] : certificate
    // [1..] : certificate Chain
    public List<X509Certificate> certificateRequest(String certificateRequest, String countryCode) throws Exception {

        String certificateAuthorityName = this.ejbcaProperties.getCertificateAuthorityName(countryCode);
        String certificateRequestBody = getJsonBody(certificateRequest, certificateAuthorityName);
        String postUrl = "https://" + this.ejbcaProperties.getCaHost() + "/ejbca/ejbca-rest-api/v1" + this.ejbcaProperties.getEndpoint();

        // Set up headers
        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");

        String clientP12ArchiveFilepath = this.ejbcaProperties.getClientP12ArchiveFilepath();
        String clientP12ArchivePassword = this.ejbcaProperties.getClientP12ArchivePassword();
        KeyManager[] keyStorePKCS12 = getKeyStoreFromPKCS12File(clientP12ArchiveFilepath, clientP12ArchivePassword);
        String ManagementCA = this.ejbcaProperties.getManagementCA();
        TrustManager[] trustManagerCA = getTrustManagerOfCACertificate(ManagementCA);

        // Get Certificate from EJBCA
        HttpResponse response = WebUtils.httpPostRequestsWithCustomSSLContext(trustManagerCA, keyStorePKCS12, postUrl, certificateRequestBody, headers);

        if (response.getStatusLine().getStatusCode() != 201) {
            throw new Exception("Certificate was not created by EJBCA");
        }
        HttpEntity entity = response.getEntity();
        if (entity == null) {
            throw new Exception("Message from EJBCA is empty");
        }
        InputStream inStream = entity.getContent();
        String result = WebUtils.convertStreamToString(inStream);

        return getCertificateFromHttpResponse(result);
    }

    private String getJsonBody(String certificateRequest, String certificateAuthorityName) {
        JSONObject JsonBody = new JSONObject();
        JsonBody.put("certificate_request", certificateRequest);
        JsonBody.put("certificate_profile_name", this.ejbcaProperties.getCertificateProfileName());
        JsonBody.put("end_entity_profile_name", this.ejbcaProperties.getEndEntityProfileName());
        JsonBody.put("certificate_authority_name", certificateAuthorityName);
        JsonBody.put("username", this.ejbcaProperties.getUsername());
        JsonBody.put("password", this.ejbcaProperties.getPassword());
        JsonBody.put("include_chain", this.ejbcaProperties.getIncludeChain());
        return JsonBody.toString();
    }

    private static KeyManager[] getKeyStoreFromPKCS12File(String PKCS12File, String PKCS12password) throws Exception {

        // Load PKCS#12 certificate
        KeyStore clientStore = KeyStore.getInstance("PKCS12");
        char[] password = PKCS12password.toCharArray();
        FileInputStream fis = new FileInputStream(PKCS12File);
        clientStore.load(fis, password);

        // Create KeyManagerFactory
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(clientStore, password);

        return keyManagerFactory.getKeyManagers();
    }

    private static TrustManager[] getTrustManagerOfCACertificate(String CAFilepath) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        if (CAFilepath == null) {
            return tmf.getTrustManagers();
        }

        CertificateFactory certificateFactory = CertificateFactory.getInstance("x509");
        FileInputStream caInputStream = new FileInputStream(CAFilepath);
        X509Certificate caCertificate = (X509Certificate) certificateFactory.generateCertificate(caInputStream);

        KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        caKeyStore.load(null, null);
        caKeyStore.setCertificateEntry("ca", caCertificate);
        tmf.init(caKeyStore);
        return tmf.getTrustManagers();
    }

    // [0] : certificate
    // [1..] : certificate Chain
    private List<X509Certificate> getCertificateFromHttpResponse(String result) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();

        JSONObject jsonResult;
        try{
            jsonResult = new JSONObject(result);
        }
        catch (JSONException e){
            throw new Exception("Response from EJBCA doesn't contain a correctly formatted json string.");
        }

        if (!jsonResult.keySet().contains("certificate")){
            throw new Exception("Response from EJBCA doesn't contain a certificate value.");
        }

        String certificateContent = jsonResult.getString("certificate");
        byte[] certificateBytes = Base64.getDecoder().decode(certificateContent);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        certs.add(certificate);

        // If the response from the EJBCA includes the Certificate Chain then get the
        // Certificate Chain from the response
        boolean includeChain = this.ejbcaProperties.getIncludeChain();
        if (includeChain && jsonResult.keySet().contains("certificate_chain")) {
            JSONArray certificateChain = jsonResult.getJSONArray("certificate_chain");
            for (int i = 0; i < certificateChain.length(); i++) {
                byte[] singleCertificateBytes = Base64.getDecoder().decode(certificateChain.getString(i));
                ByteArrayInputStream inputStreamSingleCertificate = new ByteArrayInputStream(singleCertificateBytes);
                X509Certificate singleCertificate = (X509Certificate) certificateFactory
                        .generateCertificate(inputStreamSingleCertificate);
                certs.add(singleCertificate);
            }
        }
        return certs;
    }

    // If the value false is return then the issuerDN certificate is NOT revoked.
    // If the value is true then the issuerDN certificate is revoked and cannot be trusted.
    public Boolean revocationStatus(String issuerDN, String serialNumberHex) throws Exception {
        String issuerDNUrlEncode = URLEncoder.encode(issuerDN, StandardCharsets.UTF_8).replace("+", "%20");
        String getUrl = "https://" + this.ejbcaProperties.getCaHost() + "/ejbca/ejbca-rest-api/v1/certificate/"
                + issuerDNUrlEncode + "/" + serialNumberHex + "/revocationstatus";

        // Set up headers
        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");

        String clientP12ArchiveFilepath = this.ejbcaProperties.getClientP12ArchiveFilepath();
        String clientP12ArchivePassword = this.ejbcaProperties.getClientP12ArchivePassword();
        KeyManager[] keyStorePKCS12 = getKeyStoreFromPKCS12File(clientP12ArchiveFilepath, clientP12ArchivePassword);
        String ManagementCA = this.ejbcaProperties.getManagementCA();
        TrustManager[] trustManagerCA = getTrustManagerOfCACertificate(ManagementCA);
        HttpResponse response = WebUtils.httpGetRequestsWithCustomSSLContext(trustManagerCA, keyStorePKCS12, getUrl,
                headers);

        if (response.getStatusLine().getStatusCode() != 200) {
            throw new Exception("Certificate was not found.");
        }
        if (response.getStatusLine().getStatusCode() == 404) {
            return false;
        }
        HttpEntity entity = response.getEntity();
        if (entity == null) {
            throw new Exception("Message from EJBCA is empty.");
        }

        InputStream inStream = entity.getContent();
        String result = WebUtils.convertStreamToString(inStream);
        JSONObject resultJson;
        try{
            resultJson = new JSONObject(result);
        }
        catch (JSONException e){
            throw new Exception("The response from the revocation status request to EJBCA doesn't contain a correctly formatted JSON string.");
        }

        Set<String> resultJsonKeySet = resultJson.keySet();
        if(resultJsonKeySet.contains("revoked") && resultJsonKeySet.contains("issuer_dn") && resultJsonKeySet.contains("serial_number")){
            if(!resultJson.getString("issuer_dn").equals(issuerDN)){
                log.error("The issuer_dn in the revocation status response is not the one requested.");
                return true;
            }
            if(!resultJson.getString("serial_number").equals(serialNumberHex)){
                log.error("The serial_number in the revocation status response is not the one requested.");
                return true;
            }
            return resultJson.getBoolean("revoked");
        }
        else{
            log.error("Not all the expected values are present in the response, and the validation of the response can't be ensured.");
            return true;
        }




    }

}