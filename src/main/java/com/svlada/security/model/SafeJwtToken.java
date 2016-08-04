package com.svlada.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import io.jsonwebtoken.Claims;

/**
 * Raw representation of JWT Token.
 * 
 * @author vladimir.stankovic
 *
 *         May 31, 2016
 */
public final class SafeJwtToken implements JwtToken {
    private final String rawToken;
    @JsonIgnore private Claims claims;

    protected SafeJwtToken(final String token, Claims claims) {
        this.rawToken = token;
        this.claims = claims;
    }

    public String getToken() {
        return this.rawToken;
    }

    public Claims getClaims() {
        return claims;
    }
}
