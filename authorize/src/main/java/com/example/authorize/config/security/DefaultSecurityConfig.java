package com.example.authorize.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class DefaultSecurityConfig {

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http
//			.headers().frameOptions().sameOrigin()
			.cors().disable()
			.csrf().disable()
			// todo: 改成无状态形式
//			.sessionManagement()
//			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//			.and()
			.authorizeRequests(authorizeRequests ->
//				authorizeRequests
//						.antMatchers("/oauth2/**", "/userinfo", "/connect/register", "/.well-known/openid-configuration").permitAll()
//						.anyRequest().authenticated()
				authorizeRequests.anyRequest().authenticated()
			)
			.formLogin(withDefaults());
		return http.build();
	}


	@Bean
	UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user1")
				.password("password")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}

}
