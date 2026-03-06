package com.apigateway.config;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
@Order(-1)
public class RateLimitExceptionHandler implements ErrorWebExceptionHandler {

	@Override
	public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
		if (exchange.getResponse().getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
			exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
			exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

			String body = """
					{
					    "status": 429,
					    "error": "Too Many Requests",
					    "message": "Rate limit exceeded. Please slow down your requests.",
					    "path": "%s"
					}
					""".formatted(exchange.getRequest().getPath().value());

			DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(body.getBytes());

			return exchange.getResponse().writeWith(Mono.just(buffer));
		}
		return Mono.error(ex);
	}
}
