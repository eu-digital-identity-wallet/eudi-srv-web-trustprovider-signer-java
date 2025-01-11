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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import eu.europa.ec.eudi.signer.rssp.security.jwt.JwtToken;
import eu.europa.ec.eudi.signer.rssp.security.openid4vp.OpenId4VPAuthenticationToken;
import eu.europa.ec.eudi.signer.rssp.security.openid4vp.OpenId4VPUserDetailsService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final UserAuthenticationTokenProvider tokenProvider;
    private final OpenId4VPUserDetailsService customUserOID4VPDetailsService;

    public TokenAuthenticationFilter(UserAuthenticationTokenProvider tokenProvider, OpenId4VPUserDetailsService customUserOID4VPDetailsService){
        this.tokenProvider = tokenProvider;
        this.customUserOID4VPDetailsService = customUserOID4VPDetailsService;
    }

    private static final Logger logger = LoggerFactory.getLogger(TokenAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = getJwtFromRequest(request);
        if (StringUtils.hasText(jwt)) {
            JwtToken token = tokenProvider.validateToken(jwt);
            if (token.isValid()) {
                String username = token.getSubject();
                try {
                    UserDetails userDetails2 = customUserOID4VPDetailsService.loadUserByUsername(username);
                    OpenId4VPAuthenticationToken authentication2 = new OpenId4VPAuthenticationToken(userDetails2, userDetails2.getAuthorities());
                    authentication2.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication2);
                } catch (Exception ex1) {
                    logger.error("Could not set user authentication in security context", ex1);
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
