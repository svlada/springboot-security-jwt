package com.svlada.security.model;

/**
 * Scopes
 * 
 * @author vladimir.stankovic
 *
 * Aug 18, 2016
 */
public enum Scopes {
    REFRESH_TOKEN;
    
    public String authority() {
        return "ROLE_" + this.name();
    }
}
