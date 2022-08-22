package com.easy.iam.authentication.controller;

import com.easy.iam.authentication.service.AuthenticationService;
import com.easy.iam.model.AuthCode;
import com.easy.iam.model.User;
import com.easy.iam.util.Utils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.net.URI;
import java.util.Arrays;
import java.util.UUID;

import static com.easy.iam.util.Utils.getAuthCookie;
import static com.easy.iam.util.Utils.setAuthCookie;

@RestController
@RequestMapping("/auth/authenticate")
public class AuthenticationController {

    @Autowired
    AuthenticationService authenticationService;
    @Autowired
    Utils utils;

    @PostMapping()
    public String authenticate(@RequestBody @Valid User user, BindingResult bindingResult,
                               HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse){
        String auth_cookie_id = getAuthCookie(httpServletRequest);
        String userId = authenticationService.autheticateUser(user.getUser_name(), user.getPassword(), auth_cookie_id);
        return userId;
    }

    @GetMapping()
    public ResponseEntity<?> getAuthCode(@RequestParam String response_type, @RequestParam String client_id, @RequestParam String redirect_uri,
                                            @RequestParam String scope, @RequestParam String state, HttpServletRequest httpServletRequest,
                                            HttpServletResponse httpServletResponse) {
        String auth_cookie_id = getAuthCookie(httpServletRequest);
        if (null == auth_cookie_id) {
            auth_cookie_id = UUID.randomUUID().toString();
            setAuthCookie(httpServletResponse, auth_cookie_id);
        }
        String redirectUri = authenticationService.getAuthCode(client_id, null, redirect_uri, scope, state, auth_cookie_id);
        if (redirectUri.contains("code")) {
            String code = redirectUri.split("=")[1];
            return ResponseEntity.status(HttpStatus.OK).body(code);
        }
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(redirectUri)).build();
    }

    @PostMapping("/reauth")
    public String reAuthenticate(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse){
        String auth_cookie_id = getAuthCookie(httpServletRequest);
        authenticationService.reAutheticateUser(auth_cookie_id);
        auth_cookie_id = UUID.randomUUID().toString();
        setAuthCookie(httpServletResponse, auth_cookie_id);
        return "success";
    }
}
