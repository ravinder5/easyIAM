package com.easy.iam.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.springframework.data.cassandra.core.mapping.PrimaryKey;
import org.springframework.data.cassandra.core.mapping.Table;

import javax.validation.constraints.NotBlank;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Table
public class AuthCookie {
    @PrimaryKey
    @NotBlank
    private @NonNull String auth_cookie_id;
    private String user_name;
    private String user_id;
    private String client_id;
    private boolean isAuthenticated;
}
