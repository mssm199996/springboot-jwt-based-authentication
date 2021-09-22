package com.mssmfactory.springboot_jwt_based_authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity(debug = true)
public class SpringbootJwtBasedAuthentication {

    public static void main(String[] args) {
        SpringApplication.run(SpringbootJwtBasedAuthentication.class, args);
    }
}
