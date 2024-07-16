package com.vibramium.authn.config;

import com.vibramium.authn.commons.Constants;
import com.vibramium.authn.entity.Token;
import com.vibramium.authn.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.util.Objects;

@Service
public class CustomLogOutHandler implements LogoutHandler {

    private final HandlerExceptionResolver handlerExceptionResolver;

    private final TokenRepository tokenRepository;

    public CustomLogOutHandler(HandlerExceptionResolver handlerExceptionResolver, TokenRepository tokenRepository) {
        this.handlerExceptionResolver = handlerExceptionResolver;
        this.tokenRepository = tokenRepository;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader(Constants.AUTH_HEADER);
        final String token;

        try{
            if (Objects.isNull(authHeader) || !authHeader.startsWith(Constants.BEARER)) {
                return;
            }
            token = authHeader.substring(Constants.BEARER_LENGTH);
            Token dbToken = tokenRepository.findByToken(token).orElse(null);
            if(Objects.nonNull(dbToken)){
                dbToken.setExpired(true);
                dbToken.setRevoked(true);
                tokenRepository.save(dbToken);
            }
        }catch (Exception e){
            handlerExceptionResolver.resolveException(request, response, null, e);
        }
    }
}
