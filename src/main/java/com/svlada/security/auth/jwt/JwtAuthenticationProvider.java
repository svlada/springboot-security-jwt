package com.svlada.security.auth.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.svlada.security.UserService;
import com.svlada.security.auth.JwtAuthenticationToken;
import com.svlada.security.config.JwtSettings;
import com.svlada.security.model.JwtToken;
import com.svlada.security.model.UnsafeJwtToken;
import com.svlada.security.model.UserContext;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

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
    private final UserService userService;
    private final JwtSettings jwtSettings;
    
    @Autowired
    public JwtAuthenticationProvider(UserService userService, JwtSettings jwtSettings) {
        this.userService = userService;
        this.jwtSettings = jwtSettings;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UnsafeJwtToken unsafeToken = (UnsafeJwtToken) authentication.getCredentials();

        Jws<Claims> jwsClaims = unsafeToken.parseClaims(jwtSettings.getTokenSigningKey());
        String subject = jwsClaims.getBody().getSubject();
        
        UserContext context = userService.getByUsername(subject);
        
        return new JwtAuthenticationToken(context, context.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
