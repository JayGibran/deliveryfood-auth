package com.jaygibran.deliveryfood.auth.core;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Collections;

@Getter
public class AuthUser extends User {
    
    private String fullName;
    private Long userId;
    
    public AuthUser(com.jaygibran.deliveryfood.auth.domain.User user, Collection<? extends GrantedAuthority> authorities) {
        super(user.getEmail(), user.getPassword(), authorities);
        fullName = user.getName();
        userId = user.getId();
    }
}
