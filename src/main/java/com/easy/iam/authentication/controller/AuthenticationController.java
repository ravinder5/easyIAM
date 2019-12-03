package com.easy.iam.authentication.controller;

import com.easy.iam.authentication.service.AuthenticationService;
import com.easy.iam.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth/authenticate")
public class AuthenticationController {

    @Autowired
    AuthenticationService authenticationService;

    @PostMapping()
    public String authenticate(@RequestBody @Valid User user, BindingResult bindingResult){
        String userId = authenticationService.autheticateUser(user.getUser_name(), user.getPassword());
        return userId;
    }

    @GetMapping
    public RedirectView getAuthCode(@RequestParam String response_type, @RequestParam String client_id, @RequestParam String redirect_uri,
                                    @RequestParam String scope, @RequestParam String state) {
        String redirectUri = authenticationService.getAuthCode(client_id, null, redirect_uri, scope, state, "1234567890");
        return new RedirectView(redirectUri);
    }
}
