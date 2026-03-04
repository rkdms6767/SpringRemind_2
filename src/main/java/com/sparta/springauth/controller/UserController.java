package com.sparta.springauth.controller;


import com.sparta.springauth.dto.LoginRequestDto;
import com.sparta.springauth.dto.SignupRequestDto;
import com.sparta.springauth.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/user/login-page")
    public String loginPage() {
        return "login"; //RestController아니고 Controller이기 때문에 Templetes아래 파일에서 찾아와준다.
    }

    @PostMapping("/user/login") // form의 action 주소와 일치해야 합니다.
    public String login(LoginRequestDto requestDto, HttpServletResponse res) {
        try {
            userService.login(requestDto, res);
        } catch (Exception e) {
            // 로그인 실패 시 error 쿼리 파라미터를 들고 다시 로그인 페이지로!
            return "redirect:/api/user/login-page?error";
        }

        // 로그인 성공 시 메인 페이지("/")로 리다이렉트
        return "redirect:/";
    }



    @GetMapping("/user/signup")
    public String signupPage() {
        return "signup";
    }

    @PostMapping("/user/signup")
    public String signup(SignupRequestDto requestDto){
        userService.signup(requestDto);
        return "redirect:/api/user/login-page";
    }


}