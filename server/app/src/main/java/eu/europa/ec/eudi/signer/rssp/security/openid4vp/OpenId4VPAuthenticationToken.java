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

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;

public class OpenId4VPAuthenticationToken extends AbstractAuthenticationToken {
    private final String hash;
    private final String givenName;
    private final String surname;
    private final String fullName;
    private final Object principal;
    private final Object credentials;

    public OpenId4VPAuthenticationToken(String hash, String givenName, String surname) {
        super(null);
        this.hash = hash;
        this.givenName = givenName;
        this.surname = surname;
        this.fullName = givenName + " " + surname;
        this.principal = hash;
        this.credentials = null;
        super.setAuthenticated(true);
    }

    public OpenId4VPAuthenticationToken(Object userPrincipal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        UserPrincipal user = (UserPrincipal) userPrincipal;
        this.hash = user.getUsername();
        this.principal = user;
        this.credentials = user.getPassword();
        this.givenName = user.getGivenName();
        this.surname = user.getSurname();
        this.fullName = user.getName();
        super.setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public String getName() {
        return this.hash;
    }

    public String getGivenName() {
        return this.givenName;
    }

    public String getSurname() {
        return this.surname;
    }

    public String getHash() {
        return this.hash;
    }

    public String getFullName() {
        return this.fullName;
    }
}
