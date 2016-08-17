package com.svlada.user.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import com.svlada.security.UserService;
import com.svlada.security.model.UserContext;
import com.svlada.security.model.UserRole;
import com.svlada.user.repository.UserRepository;

/**
 * Mock implementation.
 * 
 * @author vladimir.stankovic
 *
 * Aug 4, 2016
 */
@Service
public class DatabaseUserService implements UserService {
    private final UserRepository userRepository;
    
    @Autowired
    public DatabaseUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    @Override
    public UserContext getByUsernameAndPassword(String username, String password) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(UserRole.ADMIN.authority()));
        return new UserContext(username, authorities);
    }
    
    @Override
    public UserContext getByUsername(String username) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(UserRole.ADMIN.authority()));
        return new UserContext(username, authorities);
    }

    public UserRepository getUserRepository() {
        return userRepository;
    }
}
