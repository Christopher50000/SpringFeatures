package org.example.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class Controller {

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user/hello")
    public String helloUser() {return "Hello User";}

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user/data")
    public String UserData() {
        return "User Data";
    }

    //Getting Principal of the user : allows us to get the username
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user/principal")
    public String UserPrinciple(Principal user) {
        String info = user.getName();
        return info;
    }

    //Getting Authentication info of the user
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user/authenticationInfo")
    public Map<String, Object> UserAuthInfo(Authentication authentication) {

        //Authentication object represents the principal (the current user) and contains important information such as:
        // The username (or email).
        // The credentials (usually the password, but can be null for stateless authentication systems like JWT).
        // The authorities (roles or permissions granted to the user).

        Jwt jwt = (Jwt) authentication.getPrincipal(); // casting to get the JWT object in order to get the claims
        return Map.of(
                "Username", jwt.getClaimAsString("preferred_username"),
                "Email", jwt.getClaimAsString("email"),
                "Authorities", authentication.getAuthorities().toString(),
                "Authenticated", authentication.isAuthenticated(),
                "Role", authentication.getAuthorities().toArray()[2].toString(),
                "Realm Access", jwt.getClaimAsString("realm_access"),
                "Resource Access", jwt.getClaimAsString("resource_access"),
                "Claim Object", jwt.getClaims().toString()

        );

    }


    @PreAuthorize("hasRole('USER')")
    @GetMapping("/test")
    public String UserTest() {
        return "User Test";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/helloAdmin")
    public String helloAdmin()
    {
        return "Hello Admin";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/data")
    public String dataAdmin()
    {
        return "Admin Data";
    }
}

