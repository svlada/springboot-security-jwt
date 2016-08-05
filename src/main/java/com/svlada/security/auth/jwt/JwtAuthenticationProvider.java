package com.svlada.security.auth.jwt;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.joda.time.DateTime;
import org.joda.time.Minutes;
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
import com.svlada.security.model.SafeJwtToken;
import com.svlada.security.model.UnsafeJwtToken;
import com.svlada.security.model.UserContext;
import com.svlada.security.service.UserService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
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
    private final TokenAuthStrategy tokenAuthStrategy;
    private final UserService userService;
    private final JwtSettings jwtSettings;    
    
    @Autowired
    public JwtAuthenticationProvider(TokenAuthStrategy tokenAuthStrategy, UserService userService, JwtSettings jwtSettings) {
        this.tokenAuthStrategy = tokenAuthStrategy;
        this.userService = userService;
        this.jwtSettings = jwtSettings;
    }
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UnsafeJwtToken unsafeToken = ((JwtAuthenticationToken) authentication).getUnsafeToken();
        
        try {
            Jws<Claims> jwsClaims = unsafeToken.parse(jwtSettings.getTokenSigningKey());
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException | SignatureException ex) {
            throw new BadCredentialsException("Invalid JWT token: ", ex);
        } catch (ExpiredJwtException expiredEx) {
            Date expDateTime = expiredEx.getClaims().getExpiration();
            
            if (expDate != null && tokenAuthStrategy.isExpired(expDate)) {
                
            }
        } 

        SafeJwtToken safeToken = ;
        Claims claims = safeToken.getClaims();
        
        JwtAuthenticationToken authToken = new JwtAuthenticationToken(userContext, safeToken, userContext.getAuthorities());

        return authToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
