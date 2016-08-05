package com.svlada.security.auth.jwt;

import com.svlada.security.model.SafeJwtToken;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 5, 2016
 */
public interface TokenAuthStrategy {
    public SafeJwtToken authenticate(String token);
}
