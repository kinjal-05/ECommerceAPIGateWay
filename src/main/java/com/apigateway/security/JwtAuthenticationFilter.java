package com.apigateway.security;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

	@Autowired
	private JwtService jwtService;

	public JwtAuthenticationFilter() {
		System.out.println("[DEBUG] JwtAuthenticationFilter initialized!");
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

		String path = exchange.getRequest().getPath().toString();
		System.out.println("[DEBUG] Request Path: " + path);

		// ✅ Public endpoints
		if (path.contains("/api/auth/login") || path.contains("/api/auth/register")
				|| path.contains("/api/auth/refresh-token")) {

			return chain.filter(exchange);
		}

		String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			return unauthorized(exchange, "Missing token");
		}

		String token = authHeader.substring(7);

		// ❌ Don't log token
		// System.out.println("Token: " + token);

		if (!jwtService.validateToken(token)) {
			return unauthorized(exchange, "Invalid token");
		}

		String username = jwtService.getUsernameFromToken(token);
		Long userId = jwtService.getUserIdFromToken(token);
		List<String> roles = jwtService.getRolesFromToken(token);

		// ✅ Add ROLE_ prefix
		var authorities = roles.stream().map(role -> new SimpleGrantedAuthority(role)).toList();

		UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities);

		// ✅ Add headers
		ServerWebExchange mutatedExchange = exchange.mutate()
				.request(
						builder -> builder.header("X-USER-EMAIL", username).header("X-USER-ID", String.valueOf(userId)))
				.build();

		// ✅ Pass mutated exchange + SecurityContext
		return chain.filter(mutatedExchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
	}

	private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
		System.out.println("[DEBUG] Unauthorized: " + message);
		exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
		return exchange.getResponse().setComplete();
	}

	@Override
	public int getOrder() {
		return -100;
	}
}