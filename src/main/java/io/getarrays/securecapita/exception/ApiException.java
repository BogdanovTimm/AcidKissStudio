package io.getarrays.securecapita.exception;

/**
 Custom Exception for every error that might occur during hadnling HTTP-Request from user
 */
public class ApiException extends RuntimeException {
    public ApiException(String message) { super(message); }
}
