package com.ge.test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class MyUserDetailsService implements UserDetailsService {
	@Autowired
	PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		if (! "rylc".equals(username)) {
			return null;
		}
		
		UserDetails user = User.withUsername("rylc").password(passwordEncoder.encode("cy"))
				.roles("ADMIN", "USER")
				.build();
		
		return user;
	}

}
