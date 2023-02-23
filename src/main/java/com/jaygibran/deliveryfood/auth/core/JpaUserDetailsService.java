package com.jaygibran.deliveryfood.auth.core;

import com.jaygibran.deliveryfood.auth.domain.User;
import com.jaygibran.deliveryfood.auth.domain.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
public class JpaUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var userNotFound = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with informed email"));
        return new AuthUser(userNotFound);
    }
}
