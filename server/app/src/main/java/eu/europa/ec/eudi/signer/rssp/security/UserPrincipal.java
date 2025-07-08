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

package eu.europa.ec.eudi.signer.rssp.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import eu.europa.ec.eudi.signer.rssp.entities.User;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class UserPrincipal implements UserDetails {
    private final String id;
    private final String givenName;
    private final String surname;
    private final String fullName;
    private final String hash;
    private final Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    public UserPrincipal(String id, String hash, String givenName, String surname,
            Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.hash = hash;
        this.givenName = givenName;
        this.surname = surname;
        this.fullName = givenName + " " + surname;
        this.authorities = authorities;
    }

    public static UserPrincipal create(User user, String givenName, String surname) {
        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(user.getRole()));
        return new UserPrincipal(
                user.getId(),
                user.getHash(),
                givenName,
                surname,
                authorities);
    }

    public static UserPrincipal create(User user, String givenName, String surname, Map<String, Object> attributes) {
        UserPrincipal userPrincipal = UserPrincipal.create(user, givenName, surname);
        userPrincipal.setAttributes(attributes);
        return userPrincipal;
    }

    public String getId() {
        return this.id;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.hash;
    }

    public String getName() {
        return this.fullName;
    }

    public String getGivenName() {
        return this.givenName;
    }

    public String getSurname() {
        return this.surname;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
}
