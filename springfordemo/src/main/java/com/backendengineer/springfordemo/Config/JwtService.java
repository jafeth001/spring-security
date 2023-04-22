package com.backendengineer.springfordemo.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "614E635266556A586E3272357538782F413F4428472B4B6250655367566B5970";

    public String extractusername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    //generate token itself from user details
    public String generatetoken(UserDetails userDetails) {
        return generatetoken(new HashMap<>(), userDetails);
    }

    //generate tokens
    public String generatetoken(
            Map<String, Object> extarctclaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extarctclaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() * 1000 * 60 * 24))
                .signWith(getsigningKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    //extract individual claims
    public <T> T extractClaims(String token, Function<Claims, T> claimResolvers) {
        Claims claims = extractallClaims(token);
        return claimResolvers.apply(claims);
    }

    //validate token
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractusername(token);
        return (username.equals(userDetails.getUsername()))&&!Tokenexpiration(token);

    }

    private boolean Tokenexpiration(String token) {
        return extractExpirationDate(token).before(new Date());
    }

    private Date extractExpirationDate(String token) {
        return extractClaims(token,Claims::getExpiration);
    }

    //extract all claims
    private Claims extractallClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getsigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getsigningKey() {
        byte[] byteskey = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(byteskey);
    }
}
