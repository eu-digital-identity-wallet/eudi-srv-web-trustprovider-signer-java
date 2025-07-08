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

package eu.europa.ec.eudi.signer.rssp.security.jwt;

public class JwtToken {
    private String rawToken;
    private String subject;
    private String type;
    private String error;
    private boolean valid;
    private boolean expired;

    public JwtToken(String subject, String type) {
        this.subject = subject;
        this.type = type;
        this.valid = true;
        this.expired = false;
    }

    public JwtToken(String subject, String type, String rawToken) {
        this.subject = subject;
        this.type = type;
        this.valid = true;
        this.expired = false;
        this.rawToken = rawToken;
    }

    private JwtToken() {
    }

    /**
     * Create an object that represent a token that's already considered invalid.
     * 
     * @param error error message explaining why the token is in valid
     * @return a new but invalid token
     */
    public static JwtToken invalidToken(String error) {
        JwtToken token = new JwtToken();
        token.valid = false;
        token.error = error;
        return token;
    }

    /**
     * Create an object that represent a token that's already expired.
     * 
     * @return a new but invalid token
     */
    public static JwtToken expiredToken() {
        JwtToken token = new JwtToken();
        token.valid = false;
        token.expired = true;
        token.error = "JWT token is expired";
        return token;
    }

    public String getRawToken() {
        return rawToken;
    }

    public void setRawToken(String rawToken) {
        this.rawToken = rawToken;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getError() {
        return error;
    }

    public boolean isValid() {
        return valid;
    }

    public boolean isExpired() {
        return expired;
    }
}
