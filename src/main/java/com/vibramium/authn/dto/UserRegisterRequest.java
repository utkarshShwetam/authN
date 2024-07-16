package com.vibramium.authn.dto;

import com.vibramium.authn.type.Role;

public record UserRegisterRequest(String firstname, String lastname, String email, String password, Role role) {
}
