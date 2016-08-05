package com.svlada.security.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import com.svlada.security.model.UserContext;
import com.svlada.security.model.UserRole;

/**
 * Mock implementation.
 * 
 * @author vladimir.stankovic
 *
 * Aug 4, 2016
 */
@Service
public class UserService {
    public UserContext loadUser(String username, String password) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(UserRole.ADMIN.authority()));
        return new UserContext(username, authorities);
    }
    
    public UserContext loadUser(String username) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(UserRole.ADMIN.authority()));
        return new UserContext(username, authorities);
    }
}
