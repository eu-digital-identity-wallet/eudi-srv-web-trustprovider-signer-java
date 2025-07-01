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

package eu.europa.ec.eudi.signer.sa.error;

import org.springframework.web.reactive.function.client.ClientResponse;

import eu.europa.ec.eudi.signer.common.ApiError;
import eu.europa.ec.eudi.signer.common.ApiErrorResponse;

public class RSSPClientException extends RuntimeException implements ApiError {

    private String code;
    private int httpCode;
    private String description;

    public RSSPClientException(ApiErrorResponse rsspServerError, int httpCode) {
        super(rsspServerError.getError_description());
        this.httpCode = httpCode;
        this.code = rsspServerError.getError();
        this.description = rsspServerError.getError_description();
    }

    public RSSPClientException(String code, int httpCode, String description) {
        super(description);
        this.code = code;
        this.httpCode = httpCode;
        this.description = description;
    }

    public RSSPClientException(ClientResponse response) {
        super(response.statusCode().toString(), response.createException().block());
        this.code = "Unexpected Client Error";
        this.httpCode = response.statusCode().value();
        this.description = response.statusCode().toString();
    }

    @Override
    public String getCode() {
        return code;
    }

    @Override
    public int getHttpCode() {
        return httpCode;
    }

    @Override
    public String getDescription() {
        return description;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public void setHttpCode(int httpCode) {
        this.httpCode = httpCode;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
