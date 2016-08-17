package com.svlada.security.endpoint;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.svlada.security.UserService;
import com.svlada.security.auth.jwt.TokenVerifier;
import com.svlada.security.config.JwtSettings;
import com.svlada.security.config.WebSecurityConfig;
import com.svlada.security.exceptions.InvalidJwtToken;
import com.svlada.security.model.JwtToken;
import com.svlada.security.model.JwtTokenFactory;
import com.svlada.security.model.UnsafeJwtToken;
import com.svlada.security.model.UserContext;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * RefreshTokenEndpoint
 * 
 * @author vladimir.stankovic
 *
 * Aug 17, 2016
 */
@RestController
public class RefreshTokenEndpoint {
    @Autowired private JwtTokenFactory tokenFactory;
    @Autowired private JwtSettings jwtSettings;
    @Autowired private UserService userService;
    @Autowired private TokenVerifier tokenVerifier;
    
    @RequestMapping(value="/api/auth/token", method=RequestMethod.GET, produces={ MediaType.APPLICATION_JSON_VALUE })
    public @ResponseBody JwtToken refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        UnsafeJwtToken unsafeToken = this.tokenFactory.createUnsafeToken(request.getHeader(WebSecurityConfig.JWT_TOKEN_HEADER_PARAM));
        
        Jws<Claims> jwsClaims = unsafeToken.parseClaims(jwtSettings.getTokenSigningKey());
        
        String subject = jwsClaims.getBody().getSubject();
        String jti = jwsClaims.getBody().getId();

        if (!tokenVerifier.verify(jti)) {
            throw new InvalidJwtToken();
        }

        UserContext userContext = userService.getByUsername(subject);
        
        return tokenFactory.createSafeToken(userContext);
    }
}
