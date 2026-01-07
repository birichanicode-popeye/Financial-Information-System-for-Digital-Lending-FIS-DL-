package com.fisdl.auth.controller;

import com.fisdl.auth.dto.*;
import com.fisdl.auth.model.User;
import com.fisdl.auth.security.JwtUtils;
import com.fisdl.auth.security.UserDetailsImpl;
import com.fisdl.auth.security.UserDetailsServiceImpl;
import com.fisdl.auth.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsServiceImpl userDetailsService;

    public AuthController(
            AuthenticationManager authenticationManager,
            JwtUtils jwtUtils,
            UserService userService,
            PasswordEncoder passwordEncoder,
            UserDetailsServiceImpl userDetailsService
    ) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        System.out.println("=== LOGIN ATTEMPT ===");
        System.out.println("Username: " + loginRequest.getUsername());
        System.out.println("Password length: " + loginRequest.getPassword().length());

        // CRITICAL DEBUG: Check password before authentication
        try {
            UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());
            String storedPassword = userDetails.getPassword();
            String inputPassword = loginRequest.getPassword();

            System.out.println("=== PASSWORD DEBUG ===");
            System.out.println("Input password: " + inputPassword);
            System.out.println("Stored password: " + storedPassword);
            System.out.println("Password starts with $2a$: " + storedPassword.startsWith("$2a$"));

            boolean manualCheck = passwordEncoder.matches(inputPassword, storedPassword);
            System.out.println("Manual password match: " + manualCheck);
            System.out.println("======================");
        } catch (Exception e) {
            System.out.println("Error in manual check: " + e.getMessage());
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            System.out.println("=== AUTHENTICATION SUCCESS ===");
            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            String jwt = jwtUtils.generateJwtToken(userDetails.getUsername());

            List<String> roles = userDetails.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            System.out.println("JWT generated for user: " + userDetails.getUsername());
            System.out.println("User roles: " + roles);

            return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), roles));
        } catch (BadCredentialsException e) {
            System.out.println("=== AUTHENTICATION FAILED ===");
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid username or password"));
        } catch (Exception e) {
            System.out.println("=== UNEXPECTED ERROR ===");
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Login error: " + e.getMessage()));
        }
    }
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        System.out.println("=== SIGNUP ATTEMPT ===");
        System.out.println("Username: " + signUpRequest.getUsername());
        System.out.println("Email: " + signUpRequest.getEmail());
        System.out.println("Roles: " + signUpRequest.getRoles());

        try {
            User user = new User();
            user.setUsername(signUpRequest.getUsername());
            user.setEmail(signUpRequest.getEmail());
            user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));

            System.out.println("Password encoded successfully");

            userService.registerUser(user, signUpRequest.getRoles());

            System.out.println("User registered successfully in database");
            return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
        } catch (Exception e) {
            System.out.println("=== SIGNUP ERROR ===");
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("Signup error: " + e.getMessage()));
        }
    }

    @GetMapping("/hello")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("Auth Service is running!");
    }

    // Debug endpoint to check user details
    @GetMapping("/debug/user/{username}")
    public ResponseEntity<?> debugUser(@PathVariable String username) {
        System.out.println("=== DEBUG USER: " + username + " ===");
        try {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            Map<String, Object> debugInfo = Map.of(
                    "username", userDetails.getUsername(),
                    "authorities", userDetails.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList()),
                    "accountNonExpired", userDetails.isAccountNonExpired(),
                    "accountNonLocked", userDetails.isAccountNonLocked(),
                    "credentialsNonExpired", userDetails.isCredentialsNonExpired(),
                    "enabled", userDetails.isEnabled(),
                    "passwordSet", userDetails.getPassword() != null && !userDetails.getPassword().isEmpty()
            );

            System.out.println("User found: " + debugInfo);
            return ResponseEntity.ok(debugInfo);
        } catch (Exception e) {
            System.out.println("User not found or error: " + e.getMessage());
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        }
    }

    // Test password encoding
    @PostMapping("/debug/test-password-hash")
    public ResponseEntity<?> testPasswordHash(@RequestBody Map<String, String> request) {
        String rawPassword = request.get("password123");
        String hash = request.get("$2a$10$ibVebnE7PeEn2OQ49bJaM.tsTTZ.2WERsMK6j3P9ZntobtXTXdbsu"); // pass the hash stored in DB
        boolean matches = passwordEncoder.matches(rawPassword, hash);

        return ResponseEntity.ok(Map.of(
                "rawPassword", rawPassword,
                "storedHash", hash,
                "matches", matches
        ));
    }

    @PostMapping("/debug/test-password")
    public ResponseEntity<?> testPassword(@RequestBody Map<String, String> request) {
        String rawPassword = request.get("password");
        String encodedPassword = passwordEncoder.encode(rawPassword);
        boolean matches = passwordEncoder.matches(rawPassword, encodedPassword);

        return ResponseEntity.ok(Map.of(
                "rawPassword", rawPassword,
                "encodedPassword", encodedPassword,
                "matches", matches
        ));
    }
}