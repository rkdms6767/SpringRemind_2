package com.sparta.springauth.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration //수동등록
@EnableWebSecurity // 스프링 Security 지원을 가능하게 함
public class WebSecurityConfig {

    // 이 메소드가 PasswordEncoder 객체를 빈으로 등록합니다.
    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt는 비밀번호를 암호화하는 가장 흔한 알고리즘입니다.
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // CSRF 설정 끄기 (JWT 기반 프로젝트에서 흔히 사용)
        http.csrf((csrf) -> csrf.disable());

        http.authorizeHttpRequests((authorizeHttpRequests) ->
                        // CSRF 설정
                authorizeHttpRequests
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                        .requestMatchers("/").permitAll() // 메인 페이지 요청 허가
                        .requestMatchers("/api/user/**").permitAll() // 로그인/회원가입 요청 허가
                        .anyRequest().authenticated() // 그 외 모든 요청 인증 처리
                //이 외에도 .hasRole(String role)특정 권한이 있는 사용자만 허가,
        );

        http.formLogin((formLogin) ->
                formLogin
                        // 로그인 View 제공 (GET /api/user/login-page) / 우리가 만든 로그인 페이지를 이용하고 싶을 때
                        .loginPage("/api/user/login-page")
                        // 로그인 처리 (POST /api/user/login)
                        .loginProcessingUrl("/api/user/login") //controller가 아닌 그 앞단에서 실행된다.
                        // 로그인 처리 후 성공 시 URL
                        .defaultSuccessUrl("/")
                        // 로그인 처리 후 실패 시 URL
                        .failureUrl("/api/user/login-page?error")
                        .permitAll()
        );


        return http.build();
    }
}