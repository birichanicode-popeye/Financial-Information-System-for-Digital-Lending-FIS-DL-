package com.fisdl.auth.security;

import com.fisdl.auth.model.User;
import com.fisdl.auth.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("=== LOADING USER: " + username + " ===");

        User user = userRepository.findByUsernameWithRoles(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found: " + username)
                );

        System.out.println("User found: " + user.getUsername());
        System.out.println("User password set: " + (user.getPassword() != null && !user.getPassword().isEmpty()));
        System.out.println("User roles: " + user.getRoles());
        System.out.println("Number of roles: " + user.getRoles().size());

        return new UserDetailsImpl(user);
    }
}