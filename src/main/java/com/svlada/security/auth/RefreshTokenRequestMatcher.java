package com.svlada.security.auth;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.svlada.security.config.WebSecurityConfig;

/**
 * Skip processing of Refresh token URL endpoint.
 * 
 * @author vladimir.stankovic
 *
 * Aug 17, 2016
 */
public class RefreshTokenRequestMatcher implements RequestMatcher {
    private AntPathRequestMatcher matcher = new AntPathRequestMatcher(WebSecurityConfig.TOKEN_REFRESH_ENTRY_POINT);
    
    @Override
    public boolean matches(HttpServletRequest request) {
        return matcher.matches(request) ? false : true;
    }
}
