package com.easy.iam.account.controller;

import com.easy.iam.model.ClientConfig;
import com.easy.iam.model.User;
import com.easy.iam.repository.ClientConfigRepository;
import com.easy.iam.repository.UserAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.UUID;

@RestController
@RequestMapping("/auth/authenticate")
public class AccountController {

    @Autowired
    UserAuthentication userAuthentication;

    @Autowired
    ClientConfigRepository clientConfigRepository;

    @PostMapping(value = "/account")
    public String createAccount(@RequestBody @Valid User user, BindingResult bindingResult,
                                HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        user.setUser_id(UUID.randomUUID().toString());
        userAuthentication.save(user);
        return user.getUser_id();
    }

    @PostMapping(value = "/client")
    public String createAccount(@RequestBody @Valid ClientConfig clientConfig, BindingResult bindingResult,
                                HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        clientConfigRepository.save(clientConfig);
        return clientConfig.getClient_id();
    }
}
