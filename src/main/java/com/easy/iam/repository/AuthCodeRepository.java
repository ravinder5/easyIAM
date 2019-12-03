package com.easy.iam.repository;

import com.easy.iam.model.AuthCode;
import org.springframework.data.repository.CrudRepository;

public interface AuthCodeRepository extends CrudRepository<AuthCode, String> {
}
