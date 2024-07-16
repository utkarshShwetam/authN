package com.vibramium.authn.handler;

import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.security.SignatureException;

import static com.vibramium.authn.commons.Constants.*;

@RestControllerAdvice
public class ExceptionsHandler extends Exception{

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception exception) {

        // TODO send this stack trace to an observability tool
        exception.printStackTrace();

        if (exception instanceof HttpMessageNotReadableException) {
            return returnProblemDetail(HttpStatus.BAD_REQUEST,DESCRIPTION,REQUEST_BODY_REQUIRED,AUTHN_EXCEPTION);
        }

        if (exception instanceof BadCredentialsException) {
            return returnProblemDetail(HttpStatus.UNAUTHORIZED,DESCRIPTION,EMAIL_PASSWORD_INCORRECT,AUTHN_EXCEPTION);
        }

        if (exception instanceof AccountStatusException) {
            return returnProblemDetail(HttpStatus.FORBIDDEN,DESCRIPTION,ACCOUNT_LOCKED,AUTHN_EXCEPTION);
        }

        if (exception instanceof AccessDeniedException) {
            return returnProblemDetail(HttpStatus.FORBIDDEN,DESCRIPTION,UNAUTHORIZED_ACCESS,AUTHN_EXCEPTION);
        }

        if (exception instanceof SignatureException) {
            return returnProblemDetail(HttpStatus.FORBIDDEN,DESCRIPTION,JWT_SIGNATURE_INVALID,AUTHN_EXCEPTION);
        }

        if (exception instanceof ExpiredJwtException) {
            return returnProblemDetail(HttpStatus.FORBIDDEN,DESCRIPTION,JWT_TOKEN_EXPIRED,AUTHN_EXCEPTION);
        }

        return returnProblemDetail(HttpStatus.INTERNAL_SERVER_ERROR,DESCRIPTION,INTERNAL_SERVER_ERROR,AUTHN_EXCEPTION);
    }


    @ExceptionHandler(BadRequestFound.class)
    ProblemDetail handleBadRequestException(BadRequestFound e) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
        problemDetail.setType(URI.create(AUTHN_EXCEPTION));
        return problemDetail;
    }


    @ExceptionHandler(DuplicateResourceFound.class)
    ProblemDetail handleDuplicateResourceException(DuplicateResourceFound e) {
        ProblemDetail problemDetail =  ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, e.getMessage());
        problemDetail.setType(URI.create(AUTHN_EXCEPTION));
        return problemDetail;
    }


    @ExceptionHandler(ResourceNotFound.class)
    ProblemDetail handleResourceNotFoundException(ResourceNotFound e) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, e.getMessage());
        problemDetail.setType(URI.create(AUTHN_EXCEPTION));
        return problemDetail;
    }

    public static class ResourceNotFound extends RuntimeException{
        public ResourceNotFound(String message){
            super(message);
        }
    }

    public static class DuplicateResourceFound extends RuntimeException{
        public DuplicateResourceFound(String message){
            super(message);
        }
    }

    public static class BadRequestFound extends RuntimeException{
        public BadRequestFound(String message){
            super(message);
        }
    }

    public static ProblemDetail returnProblemDetail(HttpStatus status, String description, String body, String uri){
        ProblemDetail problemDetail = ProblemDetail.forStatus(status);
        problemDetail.setProperty(description, body);
        problemDetail.setType(URI.create(uri));
        return problemDetail;
    }

}
