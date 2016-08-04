package com.svlada.security.model;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 4, 2016
 */
public class UserContext {
    private final String username;
    private final String email;
    private final List<GrantedAuthority> authorities;

    public UserContext(String username, String email, List<GrantedAuthority> authorities) {
        this.username = username;
        this.email = email;
        this.authorities = authorities;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }
}
