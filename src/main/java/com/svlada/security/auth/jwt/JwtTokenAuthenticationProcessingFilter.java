package com.svlada.security.auth.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.svlada.security.auth.JwtAuthenticationToken;
import com.svlada.security.auth.jwt.extractor.TokenExtractor;
import com.svlada.security.config.WebSecurityConfig;
import com.svlada.security.model.JwtTokenFactory;
import com.svlada.security.model.UnsafeJwtToken;

/**
 * Performs validation of provided JWT Token.
 * 
 * @author vladimir.stankovic
 *
 * Aug 5, 2016
 */
public class JwtTokenAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private final AuthenticationFailureHandler failureHandler;
    private final TokenExtractor tokenExtractor;
    private final JwtTokenFactory tokenFactory;
    
    @Autowired
    public JwtTokenAuthenticationProcessingFilter(AuthenticationFailureHandler failureHandler, 
            JwtTokenFactory tokenFactory,
            TokenExtractor tokenExtractor,
            String filterProcessingUrl) {
        super(filterProcessingUrl);
        this.failureHandler = failureHandler;
        this.tokenExtractor = tokenExtractor;
        this.tokenFactory = tokenFactory;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        String tokenPayload = request.getHeader(WebSecurityConfig.JWT_TOKEN_HEADER_PARAM);
        UnsafeJwtToken token = tokenFactory.createUnsafeToken(tokenExtractor.extract(tokenPayload));
        return getAuthenticationManager().authenticate(new JwtAuthenticationToken(token));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
