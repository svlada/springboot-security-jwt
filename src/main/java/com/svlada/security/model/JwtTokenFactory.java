package com.svlada.security.model;

import java.util.Collection;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

import com.svlada.security.config.JwtSettings;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Collections;

/**
 * Factory class that should be always used to create {@link JwtToken}.
 *   
 * @author vladimir.stankovic
 *
 * May 31, 2016
 */
@Component
public class JwtTokenFactory {
	@Autowired private JwtSettings settings;

	/**
	 * Factory method for issuing new JWT Tokens.
	 *  
	 * @param username
	 * @param roles
	 * @return
	 */
	public SafeJwtToken createSafeToken(UserContext userContext, final Collection<GrantedAuthority> roles) {
		if (StringUtils.isBlank(userContext.getUsername())) {
			throw new IllegalArgumentException("Cannot create JWT Token without username");
		}
		
		if (Collections.isEmpty(roles)) {
			throw new IllegalArgumentException("Cannot create JWT Token without roles");
		}
		
		DateTime currentTime = new DateTime();
		
		Claims claims = Jwts.claims(); 
		claims.put("roles", AuthorityUtils.authorityListToSet(roles));
				
		String token = Jwts.builder()
			.setIssuer(settings.getTokenIssuer())
			.setSubject(userContext.getUsername())
			.setClaims(claims)
			.setIssuedAt(currentTime.toDate())
			.setExpiration(currentTime.plusMinutes(settings.getTokenExpirationTime()).toDate())
			.signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
		.compact();
		
		return new SafeJwtToken(token, claims);
	}

	/**
	 * Unsafe version of JWT token is created.
	 * 
	 * <strong>WARNING:</strong> Token signature validation is not performed.
	 *  
	 * @param tokenPayload
	 * @return unsafe version of JWT token.
	 */
	public UnsafeJwtToken createUnsafeToken(String tokenPayload) {
		return new UnsafeJwtToken(tokenPayload);
	}
}
