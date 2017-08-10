package com.ge.test;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.GenericFilterBean;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtAuthenticationFilter extends GenericFilterBean {
	public JwtAuthenticationFilter(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}
	
	public UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

        final String HEADER_STRING = "Authorization";
        final String SECRET = "P@ssw02d";
		String token = ((HttpServletRequest)request).getHeader(HEADER_STRING);

		try {
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
			            	SecurityContextHolder.getContext()
			            		.setAuthentication(authentication);
		            	}
	            	}
	            }
	        }
	        
	        chain.doFilter(request,response);
		} catch (Exception e) {
			((HttpServletResponse)response).setStatus(HttpServletResponse.SC_FORBIDDEN);
			((HttpServletResponse)response).setContentType("text/plain");
			response.getOutputStream().println("Error while do authentication~~~~~~~~~~");
		}
	}

	private UserDetailsService userDetailsService;
}
