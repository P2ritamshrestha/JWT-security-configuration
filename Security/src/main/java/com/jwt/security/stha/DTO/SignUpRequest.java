package com.jwt.security.stha.DTO;

import lombok.Data;

@Data
public class SignUpRequest {
    private String fullName;
    private String password;
    private String username;

}
