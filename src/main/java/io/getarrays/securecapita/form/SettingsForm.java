package io.getarrays.securecapita.form;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

/**
 Representation of a body of the HTTP-Request that can be sent to website.com/api/v1/update/settings:
 <li>Whether user's account is enabled
 <li>Whether user's account is not locked
 */
@Getter
@Setter
public class SettingsForm {
    @NotNull(message = "Enabled cannot be null or empty")
    private Boolean enabled;
    @NotNull(message = "Not Locked cannot be null or empty")
    private Boolean notLocked;
}
