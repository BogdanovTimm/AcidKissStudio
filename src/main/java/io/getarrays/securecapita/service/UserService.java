package io.getarrays.securecapita.service;

import io.getarrays.securecapita.domain.User;
import io.getarrays.securecapita.dto.UserDTO;
import io.getarrays.securecapita.form.UpdateForm;
import org.springframework.web.multipart.MultipartFile;

/**
 It is like a manager that gets missions from UserResource java class instance
 and then delegate them to UserServiceImpl
 */
public interface UserService {
    /**
     <p>
     Asks UserServiceImpl to:
     <ol>
     <li>
     add a new row into [users] table using given User java class instance,
     </li>
     <li>
     return created User back
     </li>
     <li>
     send verification URL to user's email
     </li>
     <li>
     Return UserDTO java class instance
     </li>
     </ol>
     </p>
     */
    UserDTO createUser(User user);
    /**
     <p>
     Asks UserServiceImpl to:
     <ol>
     <li>
     get an existed row from [users] table using given user's email and return created User back
     </li>
     <li>
     Returns UserDTO java class instance
     </li>
     </ol>
     </p>
     */
    UserDTO getUserByEmail(String email);
    /**
     <p>
     Asks UserServiceImpl to:
     <ol>
     <li>
     Set expiration date for verification code to 24 hours
     </li>
     <li>
     Generate random 8-letters verification code
     </li>
     <li>
     Delete old verification code if it exists from [TwoFactorVerifications] table in the database
     </li>
     <li>
     Inserts new verification code into [TwoFactorVerifications] table in the database
     </li>
     <li>
     Send verification code to user's phone as an SMS
     </li>
     </ol>
     </p>
     */
    void sendVerificationCode(UserDTO user);
    /**
     <p>
     <ol>
     <li>
     Adds a new verifying code into [code] column in [twofactorverifictaions] table in the database and deletes an old one
     </li>
     <li>
     Returns UserDTO java class instance
     </li>
     </ol>
     </p>
     */
    UserDTO verifyCode(String email, String code);
    /**
     <p>
     Asks UserServiceImp to:
     <ol>
     <li>
     Set expiration time for URL for changing a password
     </li>
     <li>
     Generate a URL for changing the password
     </li>
     <li>
     Deletes previous row that represents URL for changing a password from [resetpasswordverifications] table for given user
     </li>
     <li>
     Create a new row that represents URL for changing a password in [resetpasswordverifications] table for given user
     </li>
     <li>
     Send an email with a URL to reset user's password to user's email
     </li>
     </ol>
     </p>
     */
    void resetPassword(String email);
    /**
     <p>
     Asks UserServiceImpl to:
     <ol>
     <li>
     Checks whether URL for changing a password was expired and
     </li>
     <li>
     Return User
     </li>
     <li>
     Asks MapUserDTO to return UserDTO based on given User
     </li>
     </ol>
     </p>
     */
    UserDTO verifyPasswordKey(String key);
    void updatePassword(Long userId, String password, String confirmPassword);
    /**
     <p>
     Asks UserServiceImpl to:
     <ol>
     <li>
     Change row in [user] table by set [enabled] column to true
     </li>
     <li>
     Return updated UserDTO with its roles
     </li>
     </ol>
     </p>
     */
    UserDTO verifyAccountKey(String key);
    UserDTO updateUserDetails(UpdateForm user);
    /**
     <p>
     Asks UserServiceImpl to:
     <ol>
     <li>
     Get an existed row from [users] table using given user's id and return created User back
     </li>
     <li>
     Returns UserDTO java class instance
     </li>
     </ol>
     </p>
     */
    UserDTO getUserById(Long userId);
    /**
     <p>
     Asks UserServiceImpl to:
     <ol>
     <li>
     Check that confirm password equals to original one
     </li>
     <li>
     Change a row in [users] table by changing [password] column value
     </li>
     </ol>
     </p>
     */
    void updatePassword(Long userId, String currentPassword, String newPassword, String confirmNewPassword);
    void updateUserRole(Long userId, String roleName);
    void updateAccountSettings(Long userId, Boolean enabled, Boolean notLocked);
    UserDTO toggleMfa(String email);
    void updateImage(UserDTO user, MultipartFile image);
}
