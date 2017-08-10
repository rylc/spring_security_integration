package com.ge.test;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {
	public JwtLoginFilter(String url, AuthenticationManager authManager) {
        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authManager);
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException, IOException, ServletException {

    	req.getParameter("username");
        return getAuthenticationManager().authenticate(
                new UsernamePasswordAuthenticationToken(
                		req.getParameter("username"),
                		req.getParameter("password")
                )
        );
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest req,
            HttpServletResponse rsp, FilterChain chain,
            Authentication auth) throws IOException, ServletException {

    	final long EXPIRATIONTIME = 432000000L;
        final String SECRET = "P@ssw02d";
        
        String username = auth.getName();
		String jwt = Jwts.builder()
				.setSubject(username)
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
				.signWith(SignatureAlgorithm.HS512, SECRET).compact();

		try {
			rsp.setContentType("application/json");
			rsp.setStatus(HttpServletResponse.SC_OK);
			rsp.getOutputStream().println(jwt);
		} catch (IOException e) {
			e.printStackTrace();
		}
    }


    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getOutputStream().println("Error~~~~~~~~~~~~~");
    }
}
