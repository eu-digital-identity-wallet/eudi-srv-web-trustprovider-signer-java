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

package eu.europa.ec.eudi.signer.rssp.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import eu.europa.ec.eudi.signer.csc.model.AbstractInfo;

@ConfigurationProperties(prefix = "csc")
public class CSCProperties {

    // properties mapping to the CSC /info request
    private Info info;

    // properties for controlling the API
    private Api api;

    // properties for controlling crypto algos, signing etc for CSC
    private Crypto crypto;

    public Info getInfo() {
        return info;
    }

    public void setInfo(Info info) {
        this.info = info;
    }

    public Api getApi() {
        return api;
    }

    public void setApi(Api api) {
        this.api = api;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

    // All CSC info properties are in the YAML file or environment
    public static class Info extends AbstractInfo {
    }

    public static class Crypto {
        private String keyAlgorithm;
        private int keySize;
        private String signatureAlgorithm;

        /**
         * Key generation algorithm name
         * Example: "RSA"
         */
        public String getKeyAlgorithm() {
            return keyAlgorithm;
        }

        public void setKeyAlgorithm(String keyAlgorithm) {
            this.keyAlgorithm = keyAlgorithm;
        }

        /**
         * Certificate Signature algorithm name: must correspond with the key algorithm
         * Example "SHA256WithRSA" (corresponds with "RSA")
         */
        public String getSignatureAlgorithm() {
            return signatureAlgorithm;
        }

        public void setSignatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
        }

        /**
         * Key size in bits
         * Example: 2048
         */
        public int getKeySize() {
            return keySize;
        }

        public void setKeySize(int keySize) {
            this.keySize = keySize;
        }
    }

    public static class Api {
        private int pageSize;
        private int maxPageSize;

        public int getPageSize() {
            return pageSize;
        }

        public void setPageSize(int pageSize) {
            this.pageSize = pageSize;
        }

        public int getMaxPageSize() {
            return maxPageSize;
        }

        public void setMaxPageSize(int maxPageSize) {
            this.maxPageSize = maxPageSize;
        }
    }
}
