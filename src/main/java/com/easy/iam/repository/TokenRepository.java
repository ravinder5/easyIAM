package com.easy.iam.repository;

import com.easy.iam.model.Token;
import org.springframework.data.repository.CrudRepository;

public interface TokenRepository extends CrudRepository<Token, String> {
}
