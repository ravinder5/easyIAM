package com.easy.iam.util;

import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class Utils {
    public static final String DOMAIN = "Domain";
    public static final String PATH = "Path";
    public static final String SAME_SITE = "SameSite";
    public static final String SECURE = "Secure";
    public static final String HTTP_ONLY = "HttpOnly";
    public static final String MAX_AGE = "Max-Age";
    public static final String COMMENT = "Comment";
    public static final String SET_COOKIE = "Set-Cookie";
    public static final String SEPERATOR = "; ";
    public static final String ASSIGN = "=";

    public static String getAuthCookie(HttpServletRequest httpServletRequest) {
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

    public static void setAuthCookie(HttpServletResponse httpServletResponse, String auth_cookie_id) {
//        Cookie cookie = new Cookie("auth_cookie", auth_cookie_id);
        StringBuilder cookieString = new StringBuilder();
        cookieString.append("auth_cookie").append(ASSIGN).append(auth_cookie_id).append(SEPERATOR);
        cookieString.append(SAME_SITE).append(ASSIGN).append("Lax").append(SEPERATOR);
        cookieString.append(PATH).append(ASSIGN).append("/").append(SEPERATOR);
        httpServletResponse.addHeader(SET_COOKIE, cookieString.toString());
//        httpServletResponse.addCookie(cookie);
    }
}
