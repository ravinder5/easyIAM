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
import java.util.UUID;

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
    public String autheticateUser(String username, String password, String auth_cookie_id) {
        Optional<User> user = userAuthentication.findById(username);
        Optional<AuthCookie> authCookie = authCookieRepository.findById(auth_cookie_id);
        if(user.isPresent()) {

            return user.get().getUser_id();
        }
        return null;
    }

    @Override
    public String getAuthCode(String client_id, String client_secret, String redirect_uri, String scope, String state, String auth_cookie_id) {
        Optional<ClientConfig> clientConfig = clientConfigRepository.findById(client_id);
        Optional<AuthCookie> authCookie = authCookieRepository.findById(auth_cookie_id);
        if (authCookie.get().isAuthenticated()) {
            AuthCode authCode = new AuthCode();
            authCode.setAuth_code_id(UUID.randomUUID().toString());
            authCode.setClient_id(client_id);
            authCode.setScope(clientConfig.get().getScope());
            authCode.setUser_id(authCookie.get().getUser_id());
            authCode.setUser_name(authCookie.get().getUser_name());
            authCodeRepository.save(authCode);
            return redirect_uri + "?code=" + authCode.getAuth_code_id();
        } else {
            return redirect_uri;
        }
    }
}
