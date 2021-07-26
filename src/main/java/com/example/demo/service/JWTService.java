package com.example.demo.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;

@Service
public class JWTService {
    private String privateKey = "shfdahdsfkjahfdkjadhflaksjdhfasjdfhalsjdfhskdjfhquoryqoueryiqueyriuqweryasdasdasdasdjaeoijiodhqoifiojaidufaioufoidufaopidfuasoidfuadfoiadufioewruqincqupenriqucirqwneuprqinecuqpeinrcuqewricnqweurcpjhfjbvakjdbfjhqasdyuHAJFJh";


    /*
    1.Username
    2.Issued TIme
    3.Expiration Time
    4.Authorities
     */
    public String createToken(UserDetails userDetails) {
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        HashMap<String, String> myClaims = new HashMap<>();

        for (GrantedAuthority authority : authorities) {
            myClaims.put("role", authority.getAuthority());
        }

        return Jwts.builder()
                .setIssuedAt(new Date())
                .setSubject(userDetails.getUsername())
                .claim("authorities", myClaims)
                .setExpiration(new Date(new Date().getTime() + 3600000))
                .signWith(Keys.hmacShaKeyFor(privateKey.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public String getUsernameFromToken(String token) {
        Claims body = Jwts.
                parserBuilder().
                setSigningKey(Keys.hmacShaKeyFor(privateKey.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .getBody();
        return body.getSubject();
    }
}
