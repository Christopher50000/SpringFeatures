package org.example.config;


import org.example.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class ApplicationConfiguration {

    private final UserRepository userRepository;

    public ApplicationConfiguration(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    // interface used by Spring Security to load user-specific data
    @Bean
    UserDetailsService userDetailsService()
    {
        return username -> userRepository.findByEmail(username).orElseThrow(()-> new UsernameNotFoundException("User not found"));
    }

    // used to encode passwords securely. BCrypt is a hashing algorithm that provides strong security by adding a salt to the password before hashing. This encoder will be used for encoding passwords during authentication.
    @Bean
    BCryptPasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

    @Bean// The AuthenticationManager is used to authenticate users. It delegates the actual authentication logic to an implementation like DaoAuthenticationProvider.
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception
    {
        return config.getAuthenticationManager();
    }

    @Bean// The DaoAuthenticationProvider is used for authentication by looking up the user details and comparing the password.
    AuthenticationProvider authenticationProvider()
    {
        DaoAuthenticationProvider authprovider  = new DaoAuthenticationProvider();

        authprovider.setUserDetailsService(userDetailsService());
        authprovider.setPasswordEncoder(passwordEncoder());

        return authprovider;
    }
}


//A UserDetailsService that loads user information from the database.
//A BCryptPasswordEncoder for password encryption.
//An AuthenticationManager to handle the authentication process.
//An AuthenticationProvider that uses the UserDetailsService and BCryptPasswordEncoder to authenticate users.