package com.example.spa_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // CSRF無効化（API用）
            .authorizeHttpRequests(
                authz -> authz
                    .requestMatchers("/auth/**")
                    .permitAll() // 認証エンドポイントは認証不要
                    .anyRequest()
                    .authenticated() // その他は認証が必要
            );

        return http.build();
    }
}