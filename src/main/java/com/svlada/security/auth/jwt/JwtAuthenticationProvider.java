package com.svlada.security.auth.jwt;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.svlada.security.auth.JwtAuthenticationToken;
import com.svlada.security.config.JwtSettings;
import com.svlada.security.exceptions.JwtExpiredTokenException;
import com.svlada.security.model.JwtToken;
import com.svlada.security.model.UnsafeJwtToken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * An {@link AuthenticationProvider} implementation that will use provided
 * instance of {@link JwtToken} to perform authentication.
 * 
 * @author vladimir.stankovic
 *
 * Aug 5, 2016
 */
@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtSettings jwtSettings;
    private final TokenAuthStrategy tokenAuthStrategy; 
    
    @Autowired
    public JwtAuthenticationProvider(JwtSettings jwtSettings, TokenAuthStrategy tokenAuthStrategy) {
        this.jwtSettings = jwtSettings;
        this.tokenAuthStrategy = tokenAuthStrategy;
    }
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UnsafeJwtToken token = ((JwtAuthenticationToken) authentication).getUnsafeToken();

        SafeToken safeToken = token.authenticate(tokenAuthStrategy);
        
        try {
            token.validateToken(jwtSettings.getTokenSigningKey());
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException | SignatureException ex) {
            throw new BadCredentialsException("Invalid JWT token: ", ex);
        } catch (ExpiredJwtException expiredEx) {
            throw new JwtExpiredTokenException(token, "Token expired.", expiredEx);
        }

        Claims claims = token.claims(jwtSettings.getTokenSigningKey());
        ArrayList<String> rawAuthorities = claims.get("roles", ArrayList.class);

        List<GrantedAuthority> authorities = rawAuthorities.stream()
                .map(authority -> new SimpleGrantedAuthority(authority)).collect(Collectors.toList());

        JwtAuthenticationToken authToken = new JwtAuthenticationToken(token, authorities, claims.getSubject());

        return authToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
