package com.svlada.security.model;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
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
    public Jws<Claims> parse(String signingKey) {
        return Jwts.parser().setSigningKey(signingKey).parseClaimsJws(this.token);
    }

    @Override
    public String getToken() {
        return token;
    }
}
