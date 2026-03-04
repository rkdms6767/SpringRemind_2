package com.sparta.springauth.filter;

import com.sparta.springauth.entity.User;
import com.sparta.springauth.jwt.JwtUtil;
import com.sparta.springauth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;

@Slf4j(topic = "AuthFilter")
//@Component
@Order(2)
public class AuthFilter implements Filter {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    public AuthFilter(UserRepository userRepository, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String url = httpServletRequest.getRequestURI();

//        if (StringUtils.hasText(url) &&
//                (url.startsWith("/api/user") || url.startsWith("/css") || url.startsWith("/js"))
//        ) {
//            // 회원가입, 로그인 관련 API 는 인증 필요없이 요청 진행
//            log.info("인증처리를 하지 않는 url :" + url);
//            chain.doFilter(request, response); // 다음 Filter 로 이동
//        } else {
//        이렇게 반복되는 코드문장들을 SpringSecurity를 통해
//        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
//         문장으로 정리할 수 있음.

            // 나머지 API 요청은 인증 처리 진행
            // 토큰 확인
            String tokenValue = jwtUtil.getTokenFromRequest(httpServletRequest);

            if (StringUtils.hasText(tokenValue)) { // 토큰이 존재하면 검증 시작
                // JWT 토큰 substring
                String token = jwtUtil.substringToken(tokenValue);

                // 토큰 검증
                if (!jwtUtil.validateToken(token)) {
                    throw new IllegalArgumentException("Token Error");
                }

                // 토큰에서 사용자 정보 가져오기
                Claims info = jwtUtil.getUserInfoFromToken(token);

                User user = userRepository.findByUsername(info.getSubject()).orElseThrow(() ->
                        new NullPointerException("Not Found User")
                );

                request.setAttribute("user", user); //Controller로 활용하라고 request에 setAttribute해줌.
                chain.doFilter(request, response); // 다음 Filter 로 이동. 여기서는? 이제 dispatcher통해서 해당 controller로.
            } else {
                throw new IllegalArgumentException("Not Found Token");
            }
        }
    }