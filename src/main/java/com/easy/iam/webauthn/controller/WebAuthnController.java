package com.easy.iam.webauthn.controller;

import com.easy.iam.model.AuthCookie;
import com.easy.iam.model.User;
import com.easy.iam.repository.AuthCookieRepository;
import com.easy.iam.repository.UserAuthentication;
import com.easy.iam.webauthn.data.AssertionRequestWrapper;
import com.easy.iam.webauthn.data.RegistrationRequest;
import com.easy.iam.webauthn.service.WebAuthnService;
import com.easy.iam.yubico.util.Either;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.util.List;
import java.util.Optional;

import static com.easy.iam.util.Utils.getAuthCookie;

@RestController
@Slf4j
@RequestMapping("/webauthn")
class WebAuthnController {

    @Autowired
    private WebAuthnService webAuthnService;

    @Autowired
    private AuthCookieRepository authCookieRepository;

    @Autowired
    private UserAuthentication userAuthentication;

    @PostMapping("/register")
    ResponseEntity<RegistrationRequest> startRegistration(@RequestParam("username") String username,
                                                          @RequestParam("displayName") String displayName,
                                                          @RequestParam("credentialNickname") Optional<String> credentialNickname,
                                                          @RequestParam(value = "requireResidentKey", defaultValue = "false") boolean requireResidentKey)
            throws MalformedURLException {
                log.trace("startRegistration username: {}, displayName: {}, credentialNickname: {}, requireResidentKey: {}", username, displayName, credentialNickname, requireResidentKey);

                Either<String, RegistrationRequest> result = webAuthnService.startRegistration(username, displayName, credentialNickname, requireResidentKey);

                if (result.isRight()) {
                    return ResponseEntity.status(HttpStatus.OK).body(result.right().get());
                } else {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, result.left().get());
                }

    }

    @PostMapping("/register/finish")
    ResponseEntity<WebAuthnService.SuccessfulRegistrationResult> finishRegistration(@RequestBody String responseJson) {
        log.trace("finishRegistration responseJson: {}", responseJson);

        Either<List<String>, WebAuthnService.SuccessfulRegistrationResult> result = webAuthnService.finishRegistration(responseJson);

        if (result.isRight()) {
            return ResponseEntity.status(HttpStatus.OK).body(result.right().get());
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, result.left().get().toString());
        }

    }

    @PostMapping("/authenticate")
    public ResponseEntity<AssertionRequestWrapper> startAuthentication(@RequestParam("username") Optional<String> username,
                                                                       HttpServletRequest httpServletRequest) {

        String auth_cookie_id = getAuthCookie(httpServletRequest);
        Optional<AuthCookie> authCookie = authCookieRepository.findById(auth_cookie_id);
        if (authCookie.isPresent()) {
            Either<List<String>, AssertionRequestWrapper> result = webAuthnService.startAuthentication(username);

            if (result.isRight()) {
                return ResponseEntity.status(HttpStatus.OK).body(result.right().get());
            } else {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, result.left().get().toString());
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "auth cookie not found");
        }
    }

    @PostMapping("/authenticate/finish")
    public ResponseEntity<WebAuthnService.SuccessfulAuthenticationResult> finishAuthentication(
            @RequestBody String responseJson,
            HttpServletRequest httpServletRequest) {
        String auth_cookie_id = getAuthCookie(httpServletRequest);
        Optional<AuthCookie> authCookie = authCookieRepository.findById(auth_cookie_id);
        if (authCookie.isPresent()) {
            Either<List<String>, WebAuthnService.SuccessfulAuthenticationResult> result = webAuthnService
                    .finishAuthentication(responseJson);

            if (result.isRight()) {
                Optional<User> user = userAuthentication.findById(result.right().get().getRequest().getUsername().get());
                AuthCookie authCookie1 = authCookie.get();
                authCookie1.setUser_name(result.right().get().getRequest().getUsername().get());
                authCookie1.setUser_id(user.get().getUser_id());
                authCookie1.setAuthenticated(true);
                authCookieRepository.save(authCookie1);
                return ResponseEntity.status(HttpStatus.OK).body(result.right().get());
            } else {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, result.left().get().toString());
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "auth cookie not found");
        }

    }
    
}
