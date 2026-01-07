package com.fisdl.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final UserDetailsServiceImpl userDetailsService;

    public AuthTokenFilter(JwtUtils jwtUtils, UserDetailsServiceImpl userDetailsService) {
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getServletPath();
        System.out.println("============================================");
        System.out.println("FILTER EXECUTING - Path: " + path);
        System.out.println("FILTER EXECUTING - Method: " + request.getMethod());
        System.out.println("============================================");

        try {
            String headerAuth = request.getHeader("Authorization");
            System.out.println(">>> Authorization header: " + headerAuth);

            // Only process JWT if present
            if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
                String token = headerAuth.substring(7);
                System.out.println(">>> JWT token found, validating...");

                if (jwtUtils.validateJwtToken(token)) {
                    String username = jwtUtils.getUsernameFromJwtToken(token);
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    authentication.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    System.out.println(">>> JWT valid - User authenticated: " + username);
                } else {
                    System.out.println(">>> JWT token is INVALID");
                }
            } else {
                System.out.println(">>> No Bearer token - continuing as unauthenticated");
            }
        } catch (Exception e) {
            System.out.println(">>> JWT filter exception: " + e.getMessage());
            e.printStackTrace();
            // DON'T send error response - just log and continue
            // Public endpoints don't need authentication
        }

        System.out.println(">>> Continuing filter chain for: " + path);
        // ALWAYS continue - let Spring Security's authorization rules decide
        filterChain.doFilter(request, response);
    }
}
