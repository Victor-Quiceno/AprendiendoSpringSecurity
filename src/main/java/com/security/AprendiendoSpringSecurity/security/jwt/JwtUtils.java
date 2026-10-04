package com.security.AprendiendoSpringSecurity.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

// Esta clase proveerá los métodos necesarios para trabajar con los tokens JWT
@Component
@Slf4j
public class JwtUtils {

    @Value("${jwt.secret.key}")
    private String secretKey; // Esto ayuda a firmar el token, esto garantiza la identidad del usuario

    @Value("${jwt.time.expiration}")
    private String timeExpiration; // Esto es el tiempo de validez del token, se maneja en milisegundos

    // Generar token de acceso
    public String generateAccessToken(String username){
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + Long.parseLong(timeExpiration)))
                .signWith(getSignatureKey()) // En 0.12.x infiere el algoritmo automáticamente a partir del tipo de llave
                .compact();
    }

    // Validar el token de acceso
    public boolean isTokenValid(String token){
        // Se usa try-catch porque si el token está vencido la librería devuelve un error.
        try{
            Jwts.parser()                              // En 0.12.x se usa parser() en lugar de parserBuilder()
                    .verifyWith(getSignatureKey())      // En 0.12.x se usa verifyWith() en lugar de setSigningKey()
                    .build()
                    .parseSignedClaims(token)           // En 0.12.x se usa parseSignedClaims() en lugar de parseClaimsJws()
                    .getPayload();                     // En 0.12.x se usa getPayload() en lugar de getBody()

            return true;

        }catch (Exception e){
            log.error("Token inválido, error: ".concat(e.getMessage()));
            return false;
        }
    }

    // Obtener un solo claim
    public <T> T getClaim (String token, Function<Claims, T> claimsTFunction){
        Claims claims = extractAllClaims(token);
        return claimsTFunction.apply(claims);
    }

    // Obtener username del token
    public String getUsernameFromToken(String token){
        return getClaim(token, Claims::getSubject);
    }

    // Obtener todos los claims del token
    public Claims extractAllClaims(String token){
        return Jwts.parser()                           // En 0.12.x se usa parser() en lugar de parserBuilder()
                .verifyWith(getSignatureKey())          // En 0.12.x se usa verifyWith() en lugar de setSigningKey()
                .build()
                .parseSignedClaims(token)               // En 0.12.x se usa parseSignedClaims() en lugar de parseClaimsJws()
                .getPayload();                         // En 0.12.x se usa getPayload() en lugar de getBody()
    }

    // Obtener firma del token
    // En 0.12.x se usa SecretKey (javax.crypto) en lugar de Key (java.security)
    public SecretKey getSignatureKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
