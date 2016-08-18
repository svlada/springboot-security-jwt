package com.svlada.entity;

/**
 * Enumerated {@link User} roles.
 * 
 * @author vladimir.stankovic
 *
 * Aug 16, 2016
 */
public enum Role {
    ADMIN, PREMIUM_MEMBER, MEMBER;
    
    public String authority() {
        return "ROLE_" + this.name();
    }
}
