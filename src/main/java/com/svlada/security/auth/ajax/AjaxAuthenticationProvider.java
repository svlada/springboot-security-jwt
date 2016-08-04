package com.svlada.security.auth.ajax;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import com.svlada.security.auth.JwtAuthenticationToken;
import com.svlada.security.model.JwtTokenFactory;
import com.svlada.security.model.SafeJwtToken;
import com.svlada.security.model.UserContext;
import com.svlada.security.service.UserService;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 3, 2016
 */
@Component
public class AjaxAuthenticationProvider implements AuthenticationProvider {
    private final JwtTokenFactory tokenFactory;
    private final UserService userService;
    
    @Autowired
    public AjaxAuthenticationProvider(final JwtTokenFactory tokenFactory, final UserService userService) {
        this.tokenFactory = tokenFactory;
        this.userService = userService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.notNull(authentication, "No authentication data provided.");

        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        UserContext userContext = userService.loadUser(username, password);

        SafeJwtToken safeJwtToken = tokenFactory.createSafeToken(userContext, userContext.getAuthorities());

        return new JwtAuthenticationToken(userContext, safeJwtToken, userContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
