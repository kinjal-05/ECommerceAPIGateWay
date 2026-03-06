package com.apigateway.config;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;
@Component
public class RateLimitingFilter implements GlobalFilter, Ordered {

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		return chain.filter(exchange).then(Mono.fromRunnable(() -> {
			if (exchange.getResponse().getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
				System.out.println("⚠️ Rate limit triggered for: " + exchange.getRequest().getPath());
			}
		}));
	}

	@Override
	public int getOrder() {
		return -1;
	}
}