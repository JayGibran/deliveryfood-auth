package com.jaygibran.deliveryfood.auth.core;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;

@Component
@Validated
@ConfigurationProperties("deliveryfood.jwt.keystore")
public class JwtKeyStoreProperties {
    
    @NotBlank
    private  String path;
    @NotBlank
    private  String pass;
    @NotBlank
    private  String alias;
    
    public String getPath() {
        return path;
    }

    public String getPass() {
        return pass;
    }

    public String getAlias() {
        return alias;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public void setPass(String pass) {
        this.pass = pass;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
}
