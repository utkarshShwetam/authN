package com.vibramium.authn.filter;

import com.vibramium.authn.commons.Constants;
import com.vibramium.authn.repository.TokenRepository;
import com.vibramium.authn.service.AuthenticationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.Objects;

@Component
public class UserAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationService authenticationService;
    private final UserDetailsService userDetailsService;

    private final HandlerExceptionResolver handlerExceptionResolver;

    private final TokenRepository tokenRepository;

    public UserAuthenticationFilter(AuthenticationService authenticationService, UserDetailsService userDetailsService, HandlerExceptionResolver handlerExceptionResolver, TokenRepository tokenRepository) {
        this.authenticationService = authenticationService;
        this.userDetailsService = userDetailsService;
        this.handlerExceptionResolver = handlerExceptionResolver;
        this.tokenRepository = tokenRepository;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader(Constants.AUTH_HEADER);
        final String token;
        final String username;

        try{
            if (Objects.isNull(authHeader) || !authHeader.startsWith(Constants.BEARER)) {
                filterChain.doFilter(request, response);
                return;
            }
        }catch (Exception e){
            handlerExceptionResolver.resolveException(request, response, null, e);
        }


        try {
            token = authHeader.substring(Constants.BEARER_LENGTH);
            username = authenticationService.extractUsername(token);

            if (Objects.nonNull(username) && Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                boolean tokenValidity = tokenRepository.findByToken(token).map(
                        t -> !t.getExpired() && !t.getRevoked()
                ).orElse(false);
                if (authenticationService.isTokenValid(token, userDetails) && tokenValidity) {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                }
            }
            filterChain.doFilter(request, response);
        }catch (Exception e) {
            handlerExceptionResolver.resolveException(request, response, null, e);
        }

    }

    private String validateAndReturnParameter(HttpServletRequest request, String parameterName) {
        String value = request.getParameter(parameterName);
        if (Objects.isNull(value) || value.isEmpty()) {
//            throw new GenericAuthException("invalid_request", new String [] {parameterName});
        }
        return value;
    }

}
