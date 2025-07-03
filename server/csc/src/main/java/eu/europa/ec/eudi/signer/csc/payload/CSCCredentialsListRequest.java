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

package eu.europa.ec.eudi.signer.csc.payload;

import jakarta.validation.constraints.Null;

/**
 * Body for request of credentials/list - a list, possibly paginated, of
 * credential IDs
 * From section 11.4 of the CSC API V_1.0.4.0 spec
 */
public class CSCCredentialsListRequest {

    // REQUIRED Conditional
    // The identifier associated to the identity of the credential owner.
    // This parameter SHALL NOT be present if the service authorization is
    // user-specific (see NOTE below).
    // In that case the userID is already implicit in the service access token
    // passed in the Authorization header.
    // If a user-specific service authorization is present, it SHALL NOT be allowed
    // to use this parameter to
    // obtain the list of credentials associated to a different user.
    // The remote service SHALL return an error in such case.
    // ASSINA: always throw an error if the userID is specified (see SHALL NOT
    // above)

    @Null(message = "NonNullUserId")
    private String userId;

    // OPTIONAL
    // The maximum number of items to return from this call.
    // In case this parameter is omitted or invalid (e.g. the value is too big)
    // the remote service SHALL return its own predefined maximum number of items.
    private int maxResults;

    // OPTIONAL Conditional
    // An opaque token to retrieve a new page of results.
    // The parameter is only REQUIRED to retrieve results other than the first page,
    // based on the value of maxResult.
    private String pageToken;

    // OPTIONAL
    // The clientData as defined in the Input parameter table in section 8.3.2.
    private String clientData;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public int getMaxResults() {
        return maxResults;
    }

    public void setMaxResults(int maxResults) {
        this.maxResults = maxResults;
    }

    public String getPageToken() {
        return pageToken;
    }

    public void setPageToken(String pageToken) {
        this.pageToken = pageToken;
    }

    public String getClientData() {
        return clientData;
    }

    public void setClientData(String clientData) {
        this.clientData = clientData;
    }

}
