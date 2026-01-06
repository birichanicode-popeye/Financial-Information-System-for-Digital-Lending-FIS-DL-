package com.fisdl.auth.controller;

import com.fisdl.auth.dto.LoginRequest;
import com.fisdl.auth.dto.SignupRequest;
import com.fisdl.auth.dto.MessageResponse;
import com.fisdl.auth.model.User;
import com.fisdl.auth.security.JwtUtils;
import com.fisdl.auth.security.UserDetailsImpl;
import com.fisdl.auth.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserService userService;

    public AuthController(
            AuthenticationManager authenticationManager,
            JwtUtils jwtUtils,
            UserService userService
    ) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.userService = userService;
    }

    /**
     * LOGIN ENDPOINT
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(
            @Valid @RequestBody LoginRequest loginRequest
    ) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwt = jwtUtils.generateJwtToken(userDetails.getUsername());

        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return ResponseEntity.ok(
                new com.fisdl.auth.dto.JwtResponse(jwt, userDetails.getUsername(), roles)
        );
    }

    /**
     * SIGNUP ENDPOINT
     */
    @PostMapping("/signup")
    public ResponseEntity<MessageResponse> registerUser(
            @Valid @RequestBody SignupRequest signUpRequest
    ) {
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(signUpRequest.getPassword());

        userService.registerUser(user, signUpRequest.getRoles());

        return ResponseEntity.ok(
                new MessageResponse("User registered successfully!")
        );
    }

    /**
     * HEALTH CHECK ENDPOINT
     */
    @GetMapping("/hello")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("Auth Service is running!");
    }
}
