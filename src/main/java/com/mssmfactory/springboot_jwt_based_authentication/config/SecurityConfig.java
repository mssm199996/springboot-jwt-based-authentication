package com.mssmfactory.springboot_jwt_based_authentication.config;

import com.mssmfactory.springboot_jwt_based_authentication.config.filters.JWTGeneratorFilter;
import com.mssmfactory.springboot_jwt_based_authentication.config.filters.JWTValidatorFilter;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import javax.crypto.SecretKey;
import java.util.Arrays;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("application.security.jwt.key")
    private String jwtKey;

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

        httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().cors().configurationSource(e -> {
                    CorsConfiguration configuration = new CorsConfiguration();
                    configuration.setExposedHeaders(Arrays.asList("Authorization"));
                    configuration.addAllowedOrigin("*");
                    configuration.addAllowedHeader("*");
                    configuration.addAllowedMethod("*");
                    configuration.setMaxAge(3600L);

                    return configuration;
                })
                .and()
                .addFilterBefore(new JWTValidatorFilter(secretKey.toString()), BasicAuthenticationFilter.class)
                .addFilterAfter(new JWTGeneratorFilter(secretKey.toString()), BasicAuthenticationFilter.class)
                .authorizeRequests().anyRequest().authenticated()
                .and().httpBasic()
                .and().csrf().disable();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}