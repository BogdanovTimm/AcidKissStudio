package io.getarrays.securecapita.form;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

/**
 Representation of a Body of a given POST-HTTP-Request in JSON format that consists of user's email and user's password that is sent to website.com/login
 */
@Getter
@Setter
public class LoginForm {
    @NotEmpty(message = "Email cannot be empty")
    @Email(message = "Invalid email. Please enter a valid email address")
    private String email;
    @NotEmpty(message = "Password cannot be empty") // Will be handle by handleMethodArgumentNotValid () in HandleException
    private String password;
}
