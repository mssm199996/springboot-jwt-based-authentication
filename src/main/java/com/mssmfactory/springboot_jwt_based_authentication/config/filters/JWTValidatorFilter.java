package com.mssmfactory.springboot_jwt_based_authentication.config.filters;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class JWTValidatorFilter extends OncePerRequestFilter {

    private String key;

    public JWTValidatorFilter(String key) {
        this.key = key;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String jwt = httpServletRequest.getHeader("authorization");
        SecretKey secretKey = Keys.hmacShaKeyFor(this.key.getBytes());

        if (jwt != null) {
            try {
                Jws<Claims> jwtClaims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(jwt);
                Claims body = jwtClaims.getBody();

                String username = body.getSubject();
                String authorities = body.get("authorities", String.class);
                List<GrantedAuthority> authorityCollection = Arrays.stream(authorities.split(":")).map(SimpleGrantedAuthority::new).collect(Collectors.toList());

                SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username, null, authorityCollection));
            } catch (Exception e) {
                System.out.println(e);

                throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED);
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getRequestURI().equals("/login");
    }


}
