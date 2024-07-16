package com.vibramium.authn.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class AuthenticationService {

    private final String SECRET_KEY = "lzrT5ysr0EtX8ng0TfDQxOUQrNyJLnFIvA4Tw4S63ySNtNY796vZfrG14cwHITQfQi";

    private final UserDetailsService userDetailsService;

    public AuthenticationService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }


    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Objects> extraClaims, UserDetails userDetails) {

        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                // Expiration set to 6 hr
                // TODO can add it to db to control this expiration and load it in global configuration on post construct
                .expiration(new Date(System.currentTimeMillis()+6*60*60*1000))
                .signWith(getSigningKey())
                .compact();

    }

    public boolean isTokenValid(String token, UserDetails userDetails){

        final String username = extractUsername(token);
        return Objects.equals(username, userDetails.getUsername()) && isTokenExpired(token);

    }

    public boolean isTokenValid(String token){

        final String username = extractUsername(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        return Objects.equals(username, userDetails.getUsername()) && isTokenExpired(token) ;

    }

    private boolean isTokenExpired(String token) {
        return !extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    public String extractUsername(String token){
        return extractClaims(token,Claims::getSubject);
    }

    private <T> T extractClaims(String token, Function<Claims,T> resolver){

        final Claims claim = extractAllClaims(token);
        return resolver.apply(claim);

    }

    private Claims extractAllClaims(String token) {

        return Jwts
                .parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

    }

    private SecretKey getSigningKey() {

        byte [] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);

    }

}
