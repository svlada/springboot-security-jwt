package com.svlada.security.auth.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.svlada.security.auth.JwtAuthenticationToken;
import com.svlada.security.config.JwtSettings;
import com.svlada.security.model.JwtToken;
import com.svlada.security.model.JwtTokenFactory;
import com.svlada.security.model.SafeJwtToken;
import com.svlada.security.model.UnsafeJwtToken;
import com.svlada.security.model.UserContext;
import com.svlada.security.service.UserService;

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
    private final JwtTokenFactory jwtTokenFactory;
    
    @Autowired
    public JwtAuthenticationProvider(UserService userService, JwtSettings jwtSettings, JwtTokenFactory jwtTokenFactory) {
        this.userService = userService;
        this.jwtSettings = jwtSettings;
        this.jwtTokenFactory = jwtTokenFactory;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UnsafeJwtToken unsafeToken = ((JwtAuthenticationToken) authentication).getUnsafeToken();
        
        Jws<Claims> jwsClaims = unsafeToken.parseClaims(jwtSettings.getTokenSigningKey());
        String subject = jwsClaims.getBody().getSubject();
        UserContext context = userService.loadUser(subject);
        
        SafeJwtToken safeToken = jwtTokenFactory.createSafeToken(unsafeToken.getToken(), jwsClaims.getBody());
        
        JwtAuthenticationToken authToken = new JwtAuthenticationToken(context, safeToken, context.getAuthorities());
        return authToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
