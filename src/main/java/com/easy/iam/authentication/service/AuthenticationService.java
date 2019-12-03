package com.easy.iam.authentication.service;

import org.springframework.stereotype.Service;

public interface AuthenticationService {

    public String autheticateUser(String username, String password);

    public String getAuthCode(String client_id, String client_secret, String redirect_uri, String scope, String state, String auth_cookie_id);

}
