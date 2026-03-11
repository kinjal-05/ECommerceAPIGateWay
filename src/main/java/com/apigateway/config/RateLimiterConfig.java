package com.apigateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import reactor.core.publisher.Mono;

@Configuration
public class RateLimiterConfig {

	@Bean
	@Primary
	public KeyResolver ipKeyResolver() {
		return exchange -> {
			String ip = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
			System.out.println("Rate limit key (IP): " + ip);
			return Mono.just(ip);
		};
	}

	@Bean
	public KeyResolver userKeyResolver() {
		return exchange -> Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst("X-USER-ID"))
				.defaultIfEmpty("anonymous");
	}

	@Bean
	public RedisRateLimiter redisRateLimiter() {
		return new RedisRateLimiter(1, 2, 1);
	}
}