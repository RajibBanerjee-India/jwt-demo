package ca.rajib.jwt_demo.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.logging.Logger;

@Component
public class JWTUtil {

    Logger logger = Logger.getLogger(JWTUtil.class.getSimpleName());

    @Value("${jwt.secret}")
    private String jwtSecret;
    @Value("${jwt.expiration}")
    private long jwtExpirationMs;
    private SecretKey key;

    // Initializes the key after the class is instantiated and the jwtSecret is injected,
    // preventing the repeated creation of the key and enhancing performance
    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    // Generate JWT Token
    public String generateToken(String username) {

        return Jwts.builder()
                .subject(username)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(jwtExpirationMs)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    // Get username from JWT token
    public String getUsernameFromToken(String token) {
        
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    // Validate JWT token
    public boolean validateJwtToken(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (SecurityException securityException) {
            logger.info("Invalid JWT Signature: " + securityException.getMessage());
        } catch (MalformedJwtException malformedJwtException) {
            logger.info("Invalid JWT Token: " + malformedJwtException.getMessage());
        } catch (ExpiredJwtException expiredJwtException) {
            logger.info("JWT token is expired: " + expiredJwtException.getMessage());
        } catch (UnsupportedJwtException unsupportedJwtException) {
            logger.info("JWT token is unsupported: " + unsupportedJwtException.getMessage());
        } catch (IllegalArgumentException illegalArgumentException) {
            logger.info("JWT claims string is empty: " + illegalArgumentException.getMessage());
        }
        return false;
    }
}
