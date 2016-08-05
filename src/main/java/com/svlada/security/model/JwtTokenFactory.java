package com.svlada.security.model;

import java.util.Collection;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

import com.svlada.security.config.JwtSettings;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.lang.Collections;

/**
 * Factory class that should be always used to create {@link JwtToken}.
 * 
 * @author vladimir.stankovic
 *
 *         May 31, 2016
 */
@Component
public class JwtTokenFactory {
    private final JwtSettings settings;
    
    @Autowired
    public JwtTokenFactory(JwtSettings settings) {
        this.settings = settings;
    }

    /**
     * Factory method for issuing new JWT Tokens.
     * 
     * @param username
     * @param roles
     * @return
     */
    public SafeJwtToken createSafeToken(UserContext userContext) {
        if (StringUtils.isBlank(userContext.getUsername())) {
            throw new IllegalArgumentException("Cannot create JWT Token without username");
        }

        DateTime currentTime = new DateTime();

        Claims claims = Jwts.claims().setSubject(userContext.getUsername());

        String token = Jwts.builder()
          .setClaims(claims)
          .setIssuer(settings.getTokenIssuer())
          .setIssuedAt(currentTime.toDate())
          .setExpiration(currentTime.plusMinutes(settings.getTokenExpirationTime()).toDate())
          .signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
        .compact();

        return new SafeJwtToken(token, claims);
    }
    
    public SafeJwtToken createSafeToken(String token, Claims claims) {
        return new SafeJwtToken(token, claims);
    }
    

    /**
     * Unsafe version of JWT token is created.
     * 
     * <strong>WARNING:</strong> Token signature validation is not performed.
     * 
     * @param tokenPayload
     * @return unsafe version of JWT token.
     */
    public UnsafeJwtToken createUnsafeToken(String tokenPayload) {
        return new UnsafeJwtToken(tokenPayload);
    }
}
