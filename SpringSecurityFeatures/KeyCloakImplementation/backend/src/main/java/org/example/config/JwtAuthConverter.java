package org.example.config;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();


    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractRoles(jwt).stream()
        ).collect(Collectors.toSet());



        // we need to add the username to the token so that when we use principal we can get the username instead of the sub name which is the subject ID
        return new JwtAuthenticationToken(jwt, authorities, jwt.getClaimAsString("preferred_username"));
    }

    private Collection<? extends GrantedAuthority> extractRoles(Jwt jwt) {
        Set<String> roles = new HashSet<>();

        //Wondering how the roles are extracted from the JWT?
        // Make a post to keycloak and take the auth token and look at the claims and you will see it

        // Extract roles from realm_access
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            roles.addAll((Collection<? extends String>) realmAccess.get("roles"));
        }

        // Extract roles from resource_access.demo
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null && resourceAccess.containsKey("demo")) {
            Map<String, Object> demoAccess = (Map<String, Object>) resourceAccess.get("demo");
            if (demoAccess != null && demoAccess.containsKey("roles")) {
                roles.addAll((Collection<? extends String>) demoAccess.get("roles"));
            }
        }

        // Debugging extracted roles
        System.out.println("Extracted roles: " + roles);

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(Collectors.toSet());

//        When you extract roles from a JWT or from a database, you turn them into a list of SimpleGrantedAuthority objects so Spring Security can use them like this:
//
//        java
//        List<SimpleGrantedAuthority> authorities = List.of(
//                new SimpleGrantedAuthority("ROLE_USER"),
//                new SimpleGrantedAuthority("ROLE_ADMIN")
//        );
    }



}