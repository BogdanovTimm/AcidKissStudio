package io.getarrays.securecapita.form;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

/**
 * @author Junior RT
 * @version 1.0
 * @license Get Arrays, LLC (https://getarrays.io)
 * @since 3/16/2023
 */

@Getter
@Setter
public class UpdatePasswordForm {
    @NotEmpty(message = "Current Password cannot be empty")
    private String currentPassword;
    @NotEmpty(message = "New password cannot be empty")
    private String newPassword;
    @NotEmpty(message = "Confirm password cannot be empty")
    private String confirmNewPassword;
}
