package com.ge.test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
class WebSecurityStatelessConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	AuthenticationManager authenticationManager;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//    	UsernamePasswordAuthenticationFilter upFilter = new UsernamePasswordAuthenticationFilter();
//        upFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login"));
//        upFilter.setAuthenticationManager(authenticationManager);
    
        http.csrf().disable()
        	.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        	.and()
        		.securityContext().securityContextRepository(jwtSecurityContextRepository())
        	.and()
	            .authorizeRequests()
	                .antMatchers("/login.html").permitAll()
	                .antMatchers("/api/ctx").permitAll()
	                .antMatchers("/view.html").hasRole("ADMIN")
	                .anyRequest().authenticated()
            .and()
            	.addFilterBefore(new JwtLoginFilter("/api/login", authenticationManager), UsernamePasswordAuthenticationFilter.class);
//            	.addFilterBefore(new JwtAuthenticationFilter(userDetailsService()), UsernamePasswordAuthenticationFilter.class);
//            	.formLogin()
//	            	.loginPage("/api/login").permitAll()
//	            	.successForwardUrl("/api/ctx")
//	            	.failureForwardUrl("/api/ctx");
//            	.addFilter(upFilter);

        	}
    

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}
    
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
    	DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    	provider.setPasswordEncoder(bCryptPasswordEncoder());
    	provider.setUserDetailsService(userDetailsService());
    	return provider;
    }
    
    @Bean
    public PasswordEncoder bCryptPasswordEncoder() {
    	return new BCryptPasswordEncoder();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
    	return new MyUserDetailsService();
    }
    
    @Bean
    public JwtSecurityContextRepository jwtSecurityContextRepository() {
    	JwtSecurityContextRepository jwtSecurityContextRepository = new JwtSecurityContextRepository();
    	jwtSecurityContextRepository.setUserDetailsService(userDetailsService());
    	return jwtSecurityContextRepository;
    }
}