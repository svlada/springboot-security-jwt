package com.svlada.security.auth.jwt;

import java.util.Date;

import org.joda.time.DateTime;
import org.joda.time.Minutes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import com.svlada.security.config.JwtSettings;
import com.svlada.security.exceptions.JwtExpiredTokenException;
import com.svlada.security.model.JwtTokenFactory;
import com.svlada.security.model.SafeJwtToken;
import com.svlada.security.model.UnsafeJwtToken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 5, 2016
 */
@Component
public class RefreshTokenAuthStrategy implements TokenAuthStrategy {
    private final JwtSettings jwtSettings;
    private final JwtTokenFactory tokenFactory;
    
    @Autowired
    public RefreshTokenAuthStrategy(JwtSettings jwtSettings, JwtTokenFactory tokenFactory) {
        this.jwtSettings = jwtSettings;
        this.tokenFactory = tokenFactory;
    }

    @Override
    public SafeJwtToken authenticate(UnsafeJwtToken token) {
        try {
            Jws<Claims> jwsClaims = token.parse(jwtSettings.getTokenSigningKey());
            return tokenFactory.createSafeToken(token.getToken(), jwsClaims.getBody());
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException | SignatureException ex) {
            throw new BadCredentialsException("Invalid JWT token: ", ex);
        } catch (ExpiredJwtException expiredEx) {
            Date expDateTime = expiredEx.getClaims().getExpiration();
            
            if (expDateTime == null) {
                throw new BadCredentialsException("Expiry time is not set");
            }
            
            DateTime expirationTime = new DateTime(expiredEx.getClaims().getExpiration());
            DateTime currentTime = DateTime.now();
            
            if (Minutes.minutesBetween(currentTime, expirationTime).isGreaterThan(Minutes.minutes(jwtSettings.getTokenValidationTimeframe()))) {
                throw new JwtExpiredTokenException(token, "JWT token has expired", expiredEx);
            }
            
            return refreshToken();
        } 
    }
    
    public SafeJwtToken refreshToken() {
        return null;
    }
}
