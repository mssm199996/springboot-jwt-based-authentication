package com.mssmfactory.springboot_jwt_based_authentication.config.filters;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTGeneratorFilter extends OncePerRequestFilter {

    private String key;

    public JWTGeneratorFilter(String key) {
        this.key = key;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            SecretKey secretKey = Keys.hmacShaKeyFor(this.key.getBytes());

            String jws = Jwts.builder()
                    .setSubject(authentication.getName())
                    .claim("username", authentication.getName())
                    .claim("authorities", this.getAuthorities(authentication))
                    .signWith(secretKey)
                    .compact();

            httpServletResponse.setHeader("Authorization", jws);
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest httpServletRequest) {
        return !httpServletRequest.getRequestURI().equals("/login");
    }

    private String getAuthorities(Authentication authentication) {
        StringBuilder stringBuffer = new StringBuilder();

        for (GrantedAuthority grantedAuthority : authentication.getAuthorities())
            stringBuffer.append(grantedAuthority.getAuthority() + ":");

        return stringBuffer.toString();
    }
}
