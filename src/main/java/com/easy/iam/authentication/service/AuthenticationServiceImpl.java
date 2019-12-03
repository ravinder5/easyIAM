package com.easy.iam.authentication.service;

import com.easy.iam.model.AuthCode;
import com.easy.iam.model.AuthCookie;
import com.easy.iam.model.ClientConfig;
import com.easy.iam.model.User;
import com.easy.iam.repository.AuthCodeRepository;
import com.easy.iam.repository.AuthCookieRepository;
import com.easy.iam.repository.ClientConfigRepository;
import com.easy.iam.repository.UserAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    @Autowired
    UserAuthentication userAuthentication;

    @Autowired
    ClientConfigRepository clientConfigRepository;

    @Autowired
    AuthCookieRepository authCookieRepository;

    @Autowired
    AuthCodeRepository authCodeRepository;

    @Override
    public String autheticateUser(String username, String password) {
        Optional<User> user = userAuthentication.findById(username);
        if(user.isPresent()) {
            return user.get().getUser_id();
        }
        return null;
    }

    @Override
    public String getAuthCode(String client_id, String client_secret, String redirect_uri, String scope, String state, String auth_cookie_id) {
        Optional<ClientConfig> clientConfig = clientConfigRepository.findById(client_id);
        Optional<AuthCookie> authCookie = authCookieRepository.findById(auth_cookie_id);
        AuthCode authCode = new AuthCode();
        authCodeRepository.save(authCode);
        return "1234567";
    }
}
