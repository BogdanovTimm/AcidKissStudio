package io.getarrays.securecapita.service;

import io.getarrays.securecapita.enumeration.VerificationType;

/**
 * @author Junior RT
 * @version 1.0
 * @license Get Arrays, LLC (https://getarrays.io)
 * @since 5/27/2023
 */

public interface EmailService {
    void sendVerificationEmail(String firstName, String email, String verificationUrl, VerificationType verificationType);
}
