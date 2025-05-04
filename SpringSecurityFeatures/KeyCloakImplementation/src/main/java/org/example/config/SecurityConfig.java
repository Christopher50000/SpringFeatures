package org.example.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Autowired
    JwtAuthConverter authConverter; //tells Spring how to convert JWT claims into roles/authorities.
    // Spring Boot looks for roles in a different place unless we teach it where to look.

    //It's essential when integrating with Keycloak because Keycloak puts roles in nested claims.


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/helloAdmin").hasRole("ADMIN")
                        .requestMatchers("/helloUser").hasRole("USER")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(authConverter)));
        return http.build();
    }
}
