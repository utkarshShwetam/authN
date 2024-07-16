package com.vibramium.authn.service;

import com.vibramium.authn.dto.AuthResponse;
import com.vibramium.authn.dto.AuthenticationRequest;
import com.vibramium.authn.dto.UserRegisterRequest;
import com.vibramium.authn.entity.Token;
import com.vibramium.authn.entity.User;
import com.vibramium.authn.handler.ExceptionsHandler;
import com.vibramium.authn.repository.TokenRepository;
import com.vibramium.authn.repository.UserRepository;
import com.vibramium.authn.type.Role;
import com.vibramium.authn.type.TokenType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Service
public class UserAuthenticationService {

    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;

    private final AuthenticationService authenticationService;

    private final PasswordEncoder passwordEncoder;

    private final TokenRepository tokenRepository;


    public UserAuthenticationService(AuthenticationManager authenticationManager, UserRepository userRepository, AuthenticationService authenticationService, PasswordEncoder passwordEncoder, TokenRepository tokenRepository) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.authenticationService = authenticationService;
        this.passwordEncoder = passwordEncoder;
        this.tokenRepository = tokenRepository;
    }

    public AuthResponse authenticate(AuthenticationRequest request) {

        if (Objects.isNull(request.email()) || request.email().isEmpty()) {
            throw new ExceptionsHandler.BadRequestFound("email is required");
        }

        if (Objects.isNull(request.password()) || request.password().isEmpty()) {
            throw new ExceptionsHandler.BadRequestFound("password is required");
        }
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );

        User user = userRepository.findByEmail(request.email()).orElseThrow();

        String token = authenticationService.generateToken(user);
        revokeUserTokens(user);
        Token tokenSaved = saveGeneratedToken(user, token);

        return new AuthResponse(tokenSaved.getToken());
    }
    public AuthResponse register(UserRegisterRequest request) {

        if(Objects.isNull(request.firstname()) || request.firstname().isEmpty()){
            throw new ExceptionsHandler.BadRequestFound("firstname is required");
        }

        if(Objects.isNull(request.lastname()) || request.lastname().isEmpty()){
            throw new ExceptionsHandler.BadRequestFound("lastname is required");
        }

        if(Objects.isNull(request.email()) || request.email().isEmpty()){
            throw new ExceptionsHandler.BadRequestFound("email is required");
        }

        if(Objects.isNull(request.password()) || request.password().isEmpty()){
            throw new ExceptionsHandler.BadRequestFound("password is required");
        }

        if(userRepository.findByEmail(request.email()).isPresent()){
            throw new ExceptionsHandler.DuplicateResourceFound("Email already exist");
        }


        User user = User.builder()
               .firstname(request.firstname())
               .lastname(request.lastname())
               .email(request.email())
               .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
               .build();

        User userSaved = userRepository.save(user);
        String token = authenticationService.generateToken(user);
        Token tokenSaved = saveGeneratedToken(userSaved, token);

        return new AuthResponse(tokenSaved.getToken());
    }

    public boolean validateToken(AuthResponse authResponse) {
        if(Objects.isNull(authResponse.token()) || authResponse.token().isEmpty()){
            throw new ExceptionsHandler.BadRequestFound("token is required");
        }

        try {
            boolean tokenValidity = tokenRepository.findByToken(authResponse.token()).map(
                    t -> !t.getExpired() && !t.getRevoked()
            ).orElse(false);
            return authenticationService.isTokenValid(authResponse.token()) && tokenValidity;
        }catch (Exception e) {
            System.out.println(e.getMessage());
        }

        return false;
    }

    private Token saveGeneratedToken(User userSaved, String token) {
        Token tokenSaved = Token.builder()
                .user(userSaved)
                .token(token)
                .tokenType(TokenType.BEARER)
                .expired(Boolean.FALSE)
                .revoked(Boolean.FALSE)
                .build();

        tokenRepository.save(tokenSaved);
        return tokenSaved;
    }

    private void revokeUserTokens(User user) {
        List<Token> allUserTokes = tokenRepository.findActiveTokensByUserId(user.getId());
        if(allUserTokes.isEmpty()){
            return;
        }
        allUserTokes.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(allUserTokes);
    }

}
