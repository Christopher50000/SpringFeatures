package org.example.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


// allows spring to automatically discover ad instraited by spring componet scanning
@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration; // in milliseconds

    // Extracting username from the JWT token
//    Claims is an interface in the io.jsonwebtoken (JJWT) library,
//    representing the payload data inside a JSON Web Token (JWT).
//    It holds key-value pairs (claims) that store information about the user.
    // Example: {
    //  "sub": "john_doe",
    //  "iat": 1710153600,
    //  "exp": 1710157200,
    //  "role": "USER"
    //}
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); //In JWT, the subject (sub) claim typically holds the username or user ID.
    }

//    Function<Claims, T> means:
//    Claims: The input type (which contains the JWT data).
//    T: The return type (which depends on what we want to extract).
    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims); // basically uses the method in line 22
    }


    // retrieves all the claims from the JWT token
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(getSigningKey()) //This sets the signing key for the parser. The signing key is crucial to verify the integrity of the token (i.e., ensure it has not been tampered with).
                .build()
                .parseClaimsJws(token) // Basicallly it compares the signiture of the token with the one generated using the provided key
                .getBody();
    }


    // gets the secret key:
    //HMAC (Hash-based Message Authentication Code) is a way to sign the JWT to prevent tampering.
    private Key getSigningKey() {

        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }




    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(), io.jsonwebtoken.SignatureAlgorithm.ES256)
                .compact();



    }



//    JWT Creation: generateToken → buildToken → signWith(getSigningKey()).
//    JWT Parsing: extractAllClaims(token) extracts claims.
//    Validation: isTokenValid(token, userDetails) checks username & expiration.
//            Security: Uses HMAC-SHA key and ES256 signature algorithm.


//
//    Registered Claims – Standard claims defined in JWT specs:
//
//    sub (Subject) – Usually the username or user ID.
//    iat (Issued At) – When the token was created.
//            exp (Expiration) – When the token will expire.
//            iss (Issuer) – Who issued the token.
//    aud (Audience) – Who the token is for.
//    Public Claims – Custom claims (must be unique to avoid conflicts).
//
//    Example: "role": "ADMIN" or "email": "user@example.com".
//    Private Claims – Specific to your application (not standard).
//
//    Example: "user_id": 12345.
}
