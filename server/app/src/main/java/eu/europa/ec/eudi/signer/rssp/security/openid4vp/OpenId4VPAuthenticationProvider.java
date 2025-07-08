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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

public class OpenId4VPAuthenticationProvider implements AuthenticationProvider {

    private final OpenId4VPUserDetailsService userDetailsService;

    public OpenId4VPAuthenticationProvider(OpenId4VPUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OpenId4VPAuthenticationToken auth = (OpenId4VPAuthenticationToken) authentication;
        String hash = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : auth.getHash();
        String n = hash + ";" + auth.getGivenName() + ";" + auth.getSurname();
        UserDetails userDetails = userDetailsService.loadUserByUsername(n);
        if (userDetails == null)
            throw new UsernameNotFoundException("User Not Found");
        OpenId4VPAuthenticationToken result = new OpenId4VPAuthenticationToken(
                userDetails, userDetails.getAuthorities());
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(OpenId4VPAuthenticationToken.class);
    }

}
