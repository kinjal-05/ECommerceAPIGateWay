package com.apigateway.security;

import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	private final String secret = "ChangeThisSecretKeyToAtLeast32CharactersLong!!";

	private SecretKey getSigningKey() {
		return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
	}

	public boolean validateToken(String token) {
		try {
			System.out.println("Incoming Token: " + token);
			Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
			System.out.println("Token is VALID ✅");
			return true;
		} catch (Exception e) {
			System.out.println("Invalid Token: " + e.getMessage());
			return false;
		}
	}

	public String getUsernameFromToken(String token) {
		return extractClaims(token).getSubject();
	}

	public List<String> getRolesFromToken(String token) {
		Claims claims = extractClaims(token);
		System.out.println("Claims: " + claims);
		Object rolesObj = claims.get("roles");
		System.out.println("Raw roles object: " + rolesObj);
		if (rolesObj == null) {
			System.out.println("No roles found in token ❌");
			return List.of();
		}

		if (rolesObj instanceof List<?>) {
			List<String> roles = ((List<?>) rolesObj).stream().map(Object::toString).toList();
			System.out.println("Extracted Roles: " + roles);
			return roles;
		}
		System.out.println("Roles format incorrect ❌");
		return List.of();
	}

	public Long getUserIdFromToken(String token) {
		Claims claims = extractClaims(token);
		Object userIdObj = claims.get("userId");
		System.out.println("Raw userId object: " + userIdObj);
		if (userIdObj == null) {
			System.out.println("No userId found in token ❌");
			return null;
		}

		try {
			Long userId = Long.parseLong(userIdObj.toString());
			System.out.println("Extracted userId: " + userId);
			return userId;
		} catch (Exception e) {
			System.out.println("Invalid userId format ❌");
			return null;
		}
	}

	private Claims extractClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
	}
}