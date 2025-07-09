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

package eu.europa.ec.eudi.signer.sa.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "rssp")
public class RSSPClientConfig {
    private String apiBaseUrl;
    private String cscBaseUrl;

    public String getApiBaseUrl() {
        return apiBaseUrl;
    }

    public void setApiBaseUrl(String apiBaseUrl) {
        this.apiBaseUrl = apiBaseUrl;
    }

    public String getCscBaseUrl() {
        return cscBaseUrl;
    }

    public void setCscBaseUrl(String cscBaseUrl) {
        this.cscBaseUrl = cscBaseUrl;
    }
}
