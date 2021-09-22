package com.mssmfactory.springboot_jwt_based_authentication.config.providers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Collections;

@Component
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${admin.username}")
    private String adminUsername;

    @Value("${admin.password}")
    private String adminPassword;

    @Value("${user.username}")
    private String userUsername;

    @Value("${user.password}")
    private String userPassword;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        if (username != null && password != null) {
            String cipheredAdminPassword = this.passwordEncoder.encode(this.adminPassword);
            String cipheredUserPassword = this.passwordEncoder.encode(this.userPassword);

            if (username.equals(this.adminUsername) && this.passwordEncoder.matches(password, cipheredAdminPassword))
                return new UsernamePasswordAuthenticationToken(username, password, Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN")));
            else if (username.equals(this.userUsername) && this.passwordEncoder.matches(password, cipheredUserPassword))
                return new UsernamePasswordAuthenticationToken(username, password, Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
            else throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED);
        } else throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED);
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
