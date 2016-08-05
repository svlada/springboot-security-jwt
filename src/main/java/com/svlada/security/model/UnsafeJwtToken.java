package com.svlada.security.model;

import com.svlada.security.auth.jwt.TokenAuthStrategy;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class UnsafeJwtToken implements JwtToken {
    private String token;
    
    public UnsafeJwtToken(String token) {
        this.token = token;
    }

    /**
     * Validates JWT Token signature.
     * 
     */
    public void validateToken(String signingKey) {
        Jwts.parser().setSigningKey(signingKey).parseClaimsJws(this.token);
    }
    
    /**
     * Extract Claims object from the rawToken.
     * 
     * @param signingKey
     * @return
     */
    public Claims parseClaims(String signingKey) {
        return Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token).getBody();
    }
    
    public SafeJwtToken authenticate(TokenAuthStrategy strategy) {
        return strategy.authenticate(this.token);
    }
    
    @Override
    public String getToken() {
        return token;
    }
}
