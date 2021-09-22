package com.mssmfactory.springboot_jwt_based_authentication.controllers;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("index")
    public String index() {
        return "Hello World !";
    }

    @GetMapping("admin")
    @PreAuthorize("hasRole(\"ADMIN\")")
    public String admin() {
        return "Hello Admin !";
    }

    @PostMapping("login")
    public String login() {
        return "You're logged in !";
    }
}
