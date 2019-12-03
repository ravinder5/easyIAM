package com.easy.iam.repository;

import com.easy.iam.model.AuthCookie;
import org.springframework.data.repository.CrudRepository;

public interface AuthCookieRepository extends CrudRepository<AuthCookie, String> {
}
