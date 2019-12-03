package com.easy.iam.repository;

import com.easy.iam.model.User;
import org.springframework.data.repository.CrudRepository;

public interface UserAuthentication extends CrudRepository<User, String> {
}
