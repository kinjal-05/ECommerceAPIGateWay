package com.apigateway.security;

import java.util.List;
import java.util.stream.Collectors;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private final JwtService jwtService;

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		String token = (String) authentication.getCredentials();

		if (token == null || !jwtService.validateToken(token)) {
			return Mono.empty();
		}

		String username = jwtService.getUsernameFromToken(token);
		List<String> roles = jwtService.getRolesFromToken(token);

		var authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

		return Mono.just(new UsernamePasswordAuthenticationToken(username, null, authorities));
	}
}