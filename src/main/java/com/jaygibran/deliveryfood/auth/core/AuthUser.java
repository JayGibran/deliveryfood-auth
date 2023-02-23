package com.jaygibran.deliveryfood.auth.core;

import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

@Getter
public class AuthUser extends User {
    
    private String fullName;
    
    public AuthUser(com.jaygibran.deliveryfood.auth.domain.User user) {
        super(user.getEmail(), user.getPassword(), Collections.emptyList());
        fullName = user.getName();
    }
}
