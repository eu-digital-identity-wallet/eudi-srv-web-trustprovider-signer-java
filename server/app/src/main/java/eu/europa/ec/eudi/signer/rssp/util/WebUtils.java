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

package eu.europa.ec.eudi.signer.rssp.util;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

public class WebUtils {

    public static String convertStreamToString(InputStream is) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        is.close();
        return sb.toString();
    }

    public static HttpResponse httpGetRequests(String url, Map<String, String> headers) throws Exception {
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet(url);

        for (Map.Entry<String, String> entry : headers.entrySet()) {
            request.setHeader(entry.getKey(), entry.getValue());
        }

        return httpClient.execute(request);
    }

    private static HttpResponse httpGetRequestCommon(HttpClient httpClient, String url,
            Map<String, String> headers) throws Exception {
        HttpGet request = new HttpGet(url);

        // Set headers
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            request.setHeader(entry.getKey(), entry.getValue());
        }

        // Send Post Request
        return httpClient.execute(request);
    }

    public static HttpResponse httpGetRequestsWithCustomSSLContext(TrustManager[] tm, KeyManager[] keystore,
            String url, Map<String, String> headers) throws Exception {
        // Create SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keystore, tm, null);

        HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
        return httpGetRequestCommon(httpClient, url, headers);
    }

    private static HttpResponse httpPostRequestCommon(HttpClient httpClient, String url,
            Map<String, String> headers, String body) throws Exception {
        HttpPost request = new HttpPost(url);

        // Set headers
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            request.setHeader(entry.getKey(), entry.getValue());
        }

        // Set Message Body
        StringEntity requestEntity = new StringEntity(body);
        request.setEntity(requestEntity);

        // Send Post Request
        return httpClient.execute(request);
    }

    public static HttpResponse httpPostRequest(String url, Map<String, String> headers, String body) throws Exception {
        HttpClient httpClient = HttpClients.createDefault();
        return httpPostRequestCommon(httpClient, url, headers, body);
    }

    public static HttpResponse httpPostRequestsWithCustomSSLContext(TrustManager[] tm, KeyManager[] keystore,
            String url, String jsonBody,
            Map<String, String> headers) throws Exception {
        // Create SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keystore, tm, null);

        HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
        return httpPostRequestCommon(httpClient, url, headers, jsonBody);
    }
}
