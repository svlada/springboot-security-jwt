package com.svlada.security.auth;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.svlada.security.model.JwtToken;
import com.svlada.security.model.SafeJwtToken;
import com.svlada.security.model.UnsafeJwtToken;
import com.svlada.security.model.UserContext;

/**
 * An {@link org.springframework.security.core.Authentication} implementation
 * that is designed for simple presentation of JwtToken.
 * 
 * @author vladimir.stankovic
 *
 *         May 23, 2016
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 2877954820905567501L;

    private JwtToken safeToken;
    private UnsafeJwtToken unsafeToken;

    private UserContext userContext;

    public JwtAuthenticationToken(UnsafeJwtToken unsafeToken) {
        super(null);
        this.unsafeToken = unsafeToken;
        this.setAuthenticated(false);
    }

    public JwtAuthenticationToken(UserContext userContext, SafeJwtToken token, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.safeToken = token;
        this.userContext = userContext;
        super.setAuthenticated(true);
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }
        super.setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.userContext;
    }

    public JwtToken getSafeToken() {
        return this.safeToken;
    }

    public UnsafeJwtToken getUnsafeToken() {
        return unsafeToken;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }
}
