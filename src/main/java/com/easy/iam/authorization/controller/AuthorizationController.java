package com.easy.iam.authorization.controller;

import com.easy.iam.authorization.model.TokenRequest;
import com.easy.iam.authorization.model.TokenResponse;
import com.easy.iam.authorization.service.AuthorizationService;
import com.easy.iam.model.Token;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth/tokens")
public class AuthorizationController {

    @Autowired
    AuthorizationService authorizationService;

    @PostMapping()
    public TokenResponse generateTokens(@RequestBody @Valid TokenRequest tokenRequest, BindingResult bindingResult){
        TokenResponse tokenResponse = authorizationService.generateTokens(tokenRequest);
        return tokenResponse;
    }
}
