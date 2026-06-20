package com.example.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService {

    private final String secret;
    private SecretKey key;
    private final long expirationMillis = 1000L * 60 * 60 * 24; // 24h

    public JwtService(@Value("${jwt.secret:}") String secret) {
        this.secret = secret;
    }

    @PostConstruct
    public void init() {
        if (secret == null || secret.isEmpty()) {
            this.key = Jwts.SIG.HS256.key().build();
        } else {
            byte[] keyBytes = Decoders.BASE64.decode(secret);
            this.key = Keys.hmacShaKeyFor(keyBytes);
        }
    }

    private JwtParser parser() {
        return Jwts.parser().verifyWith(key).build();
    }

    public String generateToken(String username) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + expirationMillis);
        return Jwts.builder()
                .subject(username)
                .issuedAt(now)
                .expiration(exp)
                .signWith(key)
                .compact();
    }
    
    public String extractUsername(String token) {
        Jws<Claims> claims = parser().parseSignedClaims(token);
        return claims.getPayload().getSubject();
    }

    public boolean validateToken(String token) {
        try {
            parser().parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
