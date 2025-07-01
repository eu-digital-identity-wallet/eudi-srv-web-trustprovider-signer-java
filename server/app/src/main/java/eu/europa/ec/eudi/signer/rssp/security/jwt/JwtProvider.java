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

import eu.europa.ec.eudi.signer.rssp.common.config.TokenCommonConfig;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class JwtProvider {
    private static final String TYPE_CLAIM_NAME = "type";
    private static final Logger log = LoggerFactory.getLogger(JwtProvider.class);
    private final TokenCommonConfig jwtConfig;

    public JwtProvider(TokenCommonConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
        Security.addProvider(new BouncyCastleProvider());
    }

    public JwtToken createToken(String subject) {
        Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = issuedAt.plus(jwtConfig.getLifetimeMinutes(), ChronoUnit.MINUTES);
        log.info("Issued JWT token at: {}, expires at: {}", issuedAt, expiration);
        String rawToken = buildToken(subject, issuedAt, expiration);
        log.info("Built Raw Token.");
		return new JwtToken(jwtConfig.getType(), subject, rawToken);
    }

    public JwtToken parseToken(String rawToken) {
        SecretKey sk = getSigningKey();
        Claims claims = Jwts.parserBuilder().setSigningKey(sk).build().parseClaimsJws(rawToken).getBody();
		return new JwtToken(claims.getSubject(), claims.get(TYPE_CLAIM_NAME).toString(), rawToken);
    }

    public JwtToken validateToken(String rawToken) {
        try {
            log.info("Validating Authorization Token.");
            JwtToken token = parseToken(rawToken);
            log.info("Retrieved JwtToken from Raw Token.");
            if (!token.getType().equals(jwtConfig.getType())) {
                log.error("Failed to Validate JwtToken Type");
                return JwtToken.invalidToken(String.format("Unexpected token type: should be of type %s", jwtConfig.getType()));
            } else {
                log.info("Validated JWTToken Type");
                return token;
            }
        }  catch (MalformedJwtException ex) {
            return JwtToken.invalidToken("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            return JwtToken.expiredToken();
        } catch (UnsupportedJwtException ex) {
            return JwtToken.invalidToken("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            return JwtToken.invalidToken("JWT claims string is empty.");
        }
    }

    private SecretKey getSigningKey(){
        byte[] key_bytes = Decoders.BASE64.decode(jwtConfig.getSecret());
		return Keys.hmacShaKeyFor(key_bytes);
    }

    private String buildToken(String subject, Instant issuedAt, Instant expiration) {
        return Jwts.builder()
              .setSubject(subject)
              .claim(TYPE_CLAIM_NAME, jwtConfig.getType())
              .setIssuedAt(Date.from(issuedAt))
              .setExpiration(Date.from(expiration))
              .signWith(getSigningKey(), SignatureAlgorithm.HS512)
              .compact();
    }

    public String getUsername(String token){
        SecretKey sk = getSigningKey();
        Claims claims = Jwts.parserBuilder().setSigningKey(sk).build().parseClaimsJws(token).getBody();
        return claims.getSubject();
    }

    public boolean isExpired(String token){
        SecretKey sk = getSigningKey();
        Claims claims = Jwts.parserBuilder().setSigningKey(sk).build().parseClaimsJws(token).getBody();
        return claims.getExpiration().before(new Date());
    }
}
