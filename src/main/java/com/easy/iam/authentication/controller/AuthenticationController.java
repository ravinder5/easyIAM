package com.easy.iam.authentication.controller;

import com.easy.iam.authentication.service.AuthenticationService;
import com.easy.iam.model.AuthCode;
import com.easy.iam.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.Arrays;
import java.util.UUID;

@RestController
@RequestMapping("/auth/authenticate")
public class AuthenticationController {

    @Autowired
    AuthenticationService authenticationService;

    @PostMapping()
    public String authenticate(@RequestBody @Valid User user, BindingResult bindingResult,
                               HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse){
        String auth_cookie_id = getAuthCookie(httpServletRequest);
        String userId = authenticationService.autheticateUser(user.getUser_name(), user.getPassword(), auth_cookie_id);
        return userId;
    }

    @GetMapping()
    public String getAuthCode(@RequestParam String response_type, @RequestParam String client_id, @RequestParam String redirect_uri,
                                    @RequestParam String scope, @RequestParam String state, HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse) {
        String auth_cookie_id = getAuthCookie(httpServletRequest);
        if (null == auth_cookie_id) {
            auth_cookie_id = UUID.randomUUID().toString();
            setAuthCookie(httpServletResponse, auth_cookie_id);
        }
        String redirectUri = authenticationService.getAuthCode(client_id, null, redirect_uri, scope, state, auth_cookie_id);
        return redirectUri;
    }

    private String getAuthCookie(HttpServletRequest httpServletRequest) {
        Cookie[] cookies = httpServletRequest.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("auth_cookie")) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private void setAuthCookie(HttpServletResponse httpServletResponse, String auth_cookie_id) {
        Cookie cookie = new Cookie("auth_cookie", auth_cookie_id);
        httpServletResponse.addCookie(cookie);
    }
}
