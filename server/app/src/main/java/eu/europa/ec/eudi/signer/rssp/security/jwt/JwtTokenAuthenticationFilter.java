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

import eu.europa.ec.eudi.signer.rssp.common.config.JwtConfigProperties;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import eu.europa.ec.eudi.signer.rssp.security.openid4vp.OpenId4VPAuthenticationToken;
import eu.europa.ec.eudi.signer.rssp.security.openid4vp.OpenId4VPUserDetailsService;

import java.io.IOException;

public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenAuthenticationFilter.class);
    private final JwtProvider jwtProvider;
    private final OpenId4VPUserDetailsService customUserOID4VPDetailsService;

    public JwtTokenAuthenticationFilter(JwtConfigProperties jwtConfigProperties, OpenId4VPUserDetailsService customUserOID4VPDetailsService){
        this.jwtProvider = new JwtProvider(jwtConfigProperties);
        this.customUserOID4VPDetailsService = customUserOID4VPDetailsService;
    }

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        logger.info("Retrieving JwtToken from Header.");
        String jwt = getJwtFromRequest(request);
        if(!StringUtils.hasText(jwt)){
            logger.info("It wasn't possible to retrieve the JwtToken,");
            filterChain.doFilter(request, response);
            return;
        }
        logger.info("Retrieved JwtToken from Header. Validating JwtToken.");
        JwtToken token = getToken(jwt);
        if(!token.isValid()) {
            logger.info("JwtToken Not Valid.");
            filterChain.doFilter(request, response);
            return;
        }
        logger.info("Validated JwtToken.");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = token.getSubject();
        logger.info("JWT Token Subject: {}", username);

        if(username != null && authentication == null) {
            UserPrincipal userDetails = (UserPrincipal) customUserOID4VPDetailsService.loadUserByUsername(username);
            logger.info("Retrieved UserDetails from username {}", username);

            if (isTokenValid(jwt, userDetails)) {
                logger.info("Jwt Token is valid.");
            }
            else{
                logger.info("Jwt Token is invalid.");
            }

            OpenId4VPAuthenticationToken authToken = new OpenId4VPAuthenticationToken(userDetails, userDetails.getAuthorities());
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authToken);
            logger.info("Set-up the Security Context Holder.");
            logger.info(SecurityContextHolder.getContext().getAuthentication().toString());
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

    private JwtToken getToken(String authToken){
        JwtToken token = jwtProvider.validateToken(authToken);
        if (!token.isValid()) {
            logger.error(token.getError());
        }
        return token;
    }

    private boolean isTokenValid(String token, UserPrincipal userDetails) {
        final String username = jwtProvider.getUsername(token);
		logger.info("Jwt Token Username: {}", username);
        logger.info("User Details Username: {}", userDetails.getUsername());
        logger.info("Jwt Token expired? {}", jwtProvider.isExpired(token));
        return (username.equals(userDetails.getUsername())) && !jwtProvider.isExpired(token);
    }
}
