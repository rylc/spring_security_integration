package com.ge.test;

import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtSecurityContextRepository implements SecurityContextRepository {
	private static final String HEADER_STRING = "Authorization";

	public UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {

		try {
			HttpServletRequest request = requestResponseHolder.getRequest();
	        final String SECRET = "P@ssw02d";
			String token = request.getHeader(HEADER_STRING);
			
	        if (token != null) {
	            Claims claims = Jwts.parser()
	                    .setSigningKey(SECRET)
	                    .parseClaimsJws(token)
	                    .getBody();
	
	            String username = claims.getSubject();
	            if (username != null) {
	            	UserDetails userDetails = userDetailsService.loadUserByUsername(username);
	            	if (userDetails != null) {
		            	Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
		            	if (authorities != null) {
			            	Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
							SecurityContext securityContext = new SecurityContextImpl();
							securityContext.setAuthentication(authentication);
							
							return securityContext;
		            	}
	            	}
	            }
	        }
	        
	        return SecurityContextHolder.createEmptyContext();
		} catch (Exception e) {
			return SecurityContextHolder.createEmptyContext();
		}
	}

	@Override
	public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
		return;
	}

	@Override
	public boolean containsContext(HttpServletRequest request) {
		return request.getHeader(HEADER_STRING) != null;
	}

	private UserDetailsService userDetailsService;
}
