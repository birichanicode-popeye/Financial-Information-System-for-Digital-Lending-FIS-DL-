package com.fisdl.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthTokenFilter authTokenFilter;
    private final UserDetailsServiceImpl userDetailsService;

    public SecurityConfig(AuthTokenFilter authTokenFilter,
                          UserDetailsServiceImpl userDetailsService) {
        this.authTokenFilter = authTokenFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());

        return authManagerBuilder.build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        System.out.println("========================================");
        System.out.println("CONFIGURING SECURITY FILTER CHAIN");
        System.out.println("========================================");

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    System.out.println("Configuring public paths...");
                    auth
                            .requestMatchers("/api/auth/login").permitAll()
                            .requestMatchers("/api/auth/signup").permitAll()
                            .requestMatchers("/api/auth/hello").permitAll()
                            .requestMatchers("/api/auth/debug/**").permitAll()  // Debug endpoints
                            .requestMatchers("/h2-console/**").permitAll()
                            .anyRequest().authenticated();
                })
                .headers(headers -> headers.frameOptions(frame -> frame.disable()))
                .addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        System.out.println("Security filter chain configured!");
        return http.build();
    }
}
