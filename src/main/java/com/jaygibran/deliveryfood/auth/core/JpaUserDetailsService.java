package com.jaygibran.deliveryfood.auth.core;

import com.jaygibran.deliveryfood.auth.domain.User;
import com.jaygibran.deliveryfood.auth.domain.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.stream.Collectors;

@AllArgsConstructor
@Service
public class JpaUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with informed email"));
        return new AuthUser(user, getAuthorities(user));
    }
    
    private Collection<GrantedAuthority> getAuthorities(User user){
        return user.getGroups().stream()
                .flatMap(group -> group.getPermissions().stream())
                .map(permission -> new SimpleGrantedAuthority(permission.getName().toUpperCase()))
                .collect(Collectors.toSet());
    }
}
