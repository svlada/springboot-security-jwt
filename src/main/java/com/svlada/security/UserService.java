package com.svlada.security;

import com.svlada.security.model.UserContext;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 17, 2016
 */
public interface UserService {
    public UserContext getByUsername(String username);
    public UserContext getByUsernameAndPassword(String username, String password);
}
