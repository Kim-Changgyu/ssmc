package com.prgrms.devcourse.controller;

import com.prgrms.devcourse.jwt.JwtAuthentication;
import com.prgrms.devcourse.user.UserDto;
import com.prgrms.devcourse.user.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserRestController {

    private final UserService userService;

    public UserRestController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/user/me")
    public UserDto me(@AuthenticationPrincipal JwtAuthentication authentication) {
        return userService.findByUsername(authentication.username)
                .map(user -> new UserDto(authentication.token, authentication.username, user.getGroup().getName()))
                .orElseThrow(() -> new IllegalArgumentException("Could not found user for" + authentication.username));
    }
}
