package org.example.config;



import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.example.service.JwtService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component //ensures the filter runs once per request. It is useful when you want to process incoming requests at a certain point in the filter chain (e.g., before authentication).
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // handle exceptions during the filtering process.
    private final HandlerExceptionResolver handlerExceptionResolver;

    // from jwtService class
    private final JwtService jwtService;

    //is a Spring Security service used to retrieve user details from the database.
    private final UserDetailsService userDetailsService;


    public JwtAuthenticationFilter(HandlerExceptionResolver handlerExceptionResolver, JwtService jwtService, UserDetailsService userDetailsService) {
        this.handlerExceptionResolver = handlerExceptionResolver;
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    // This method is called by the Spring Security framework and is responsible for authenticating the user for every request
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,@NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }


        try
        {
            final String jwt = authHeader.substring(7);
            final String userEmail = jwtService.extractUsername(jwt);

//            Authentication object represents the principal (the current user) and contains important information such as:
//            The username (or email).
//            The credentials (usually the password, but can be null for stateless authentication systems like JWT).
//            The authorities (roles or permissions granted to the user).
            // Authentication object is then set in the SecurityContext using SecurityContextHolder.getContext().setAuthentication(authToken);. This allows the user to be considered authenticated within the context of the request.


            // basically it checks if the user is already authenticated
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();


            //the user is not already authenticated), the filter tries to authenticate the user by:
            if(userEmail!=null && authentication==null)
            {
                //Calling userDetailsService.loadUserByUsername(userEmail) to retrieve the UserDetails object (i.e., user information such as roles).
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                //If the JWT is valid (jwtService.isTokenValid(jwt, userDetails)), it creates a UsernamePasswordAuthenticationToken with the user's details and authorities,  represents the authenticated user and their granted authorities.
                if(jwtService.isTokenValid(jwt,userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    ); //  represent the authentication request. It contains the user details, credentials (in this case, null for password because JWT is stateless), and authorities (roles/permissions).

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); //used to set additional details for the authentication token, such as the remote address, session ID, etc. These are typically useful for more granular authentication checks (e.g., IP address or session ID based restrictions).
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

            filterChain.doFilter(request, response);
        }
        catch (Exception e)
        {
            handlerExceptionResolver.resolveException(request, response, null, e);
        }


    }
//    Extracts and validates the JWT from the Authorization header.
//    Extracts the username/email from the JWT.
//    Checks if the user is already authenticated.
//    If not authenticated, retrieves the user details from the UserDetailsService and validates the JWT.
//    If the JWT is valid, it creates a UsernamePasswordAuthenticationToken with the user’s details and sets it in the SecurityContext, effectively authenticating the user for that request.
}
