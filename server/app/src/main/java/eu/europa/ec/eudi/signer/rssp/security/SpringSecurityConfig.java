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

import static eu.europa.ec.eudi.signer.common.SignerConstants.CSC_URL_ROOT;

import eu.europa.ec.eudi.signer.rssp.common.config.JwtConfigProperties;
import eu.europa.ec.eudi.signer.rssp.repository.UserRepository;
import eu.europa.ec.eudi.signer.rssp.security.jwt.JwtTokenAuthenticationFilter;
import eu.europa.ec.eudi.signer.rssp.security.openid4vp.OpenId4VPAuthenticationProvider;
import eu.europa.ec.eudi.signer.rssp.security.openid4vp.OpenId4VPUserDetailsService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(SpringSecurityConfig.class);

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, @Autowired JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter) throws Exception {
        return http
              .cors(Customizer.withDefaults())
              .csrf(AbstractHttpConfigurer::disable)
              .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
              )
              .exceptionHandling(exceptions ->
                    exceptions.authenticationEntryPoint((request, response, exception) -> {
                        logger.error("Responding with unauthorized error. Message - {}", exception.getMessage(), exception);
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("Unauthorized");
                    })
              )
              .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/swagger-ui/**").permitAll()
                    .requestMatchers("/v3/api-docs/**").permitAll()
                    .requestMatchers("/auth/**").permitAll()
                    .requestMatchers(CSC_URL_ROOT + "/info").permitAll()
                    .anyRequest().authenticated()
              )
              .addFilterBefore(jwtTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
              .build();
    }

    @Bean
    public JwtTokenAuthenticationFilter jwtAuthenticationFilter(JwtConfigProperties jwtConfigProperties, OpenId4VPUserDetailsService customUserOID4VPDetailsService){
        return new JwtTokenAuthenticationFilter(jwtConfigProperties, customUserOID4VPDetailsService);
    }

    @Bean
    public OpenId4VPUserDetailsService userDetailsService(UserRepository userRepository){
        return new OpenId4VPUserDetailsService(userRepository);
    }

    @Bean
    public OpenId4VPAuthenticationProvider authenticationProvider(OpenId4VPUserDetailsService userDetailsService){
        return new OpenId4VPAuthenticationProvider(userDetailsService);
    }

    @Bean
    public AuthenticationManager authenticationManager(OpenId4VPAuthenticationProvider authenticationProvider) {
        return new ProviderManager(authenticationProvider);
    }

}