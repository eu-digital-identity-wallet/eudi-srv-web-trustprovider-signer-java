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

import java.util.List;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;

public class EJBCAProperties {
    private String caHost;
    private String clientP12ArchiveFilepath;
    private String clientP12ArchivePassword;
    private String managementCA;
    private String endpoint;
    private String certificateProfileName;
    private String endEntityProfileName;
    private String username;
    private String password;
    private boolean includeChain;
    private List<CountryConfig> countries;

    public void setCountries(List<CountryConfig> countries) {
        this.countries = countries;
    }

    public String getCertificateAuthorityName(String country) {
        String def = null;
        boolean found = false;
        for (int i = 0; i < countries.size() && !found; i++) {
            CountryConfig c = this.countries.get(i);
            if (c.getCountry().equals(country)) {
                def = c.getCertificateAuthorityName();
                found = true;
            } else if (c.getCountry().equals("default")) {
                def = c.getCertificateAuthorityName();
            }
        }
        return def;
    }

    public String getCaHost() {
        return caHost;
    }

    public String getClientP12ArchiveFilepath() {
        return clientP12ArchiveFilepath;
    }

    public String getClientP12ArchivePassword() {
        return clientP12ArchivePassword;
    }

    public String getManagementCA() {
        return managementCA;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public boolean getIncludeChain() {
        return includeChain;
    }

    public void setCaHost(String caHost) {
        this.caHost = caHost;
    }

    public void setClientP12ArchiveFilepath(String clientP12ArchiveFilepath) {
        this.clientP12ArchiveFilepath = clientP12ArchiveFilepath;
    }

    public void setClientP12ArchivePassword(String clientP12ArchivePassword) {
        this.clientP12ArchivePassword = clientP12ArchivePassword;
    }

    public void setManagementCA(String managementCA) {
        this.managementCA = managementCA;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public void setCertificateProfileName(String certificateProfileName) {
        this.certificateProfileName = certificateProfileName;
    }

    public void setEndEntityProfileName(String endEntityProfileName) {
        this.endEntityProfileName = endEntityProfileName;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setIncludeChain(boolean includeChain) {
        this.includeChain = includeChain;
    }

    public static class CountryConfig {
        @NotNull
        private String country;

        @NotNull
        private String certificateAuthorityName;

        public String getCountry() {
            return this.country;
        }

        public void setCountry(String country) {
            this.country = country;
        }

        public String getCertificateAuthorityName() {
            return this.certificateAuthorityName;
        }

        public void setCertificateAuthorityName(String certificateAuthorityName) {
            this.certificateAuthorityName = certificateAuthorityName;
        }
    }
}
