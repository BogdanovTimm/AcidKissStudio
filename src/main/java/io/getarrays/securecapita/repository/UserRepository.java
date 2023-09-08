package io.getarrays.securecapita.repository;

import io.getarrays.securecapita.domain.User;
import io.getarrays.securecapita.dto.UserDTO;
import io.getarrays.securecapita.form.UpdateForm;
import org.springframework.web.multipart.MultipartFile;

import java.util.Collection;

/**
 * It is like a manager that gets missions from UserServiceImpl
 * and then delegate them to UserRepositoryImpl
 */
public interface UserRepository<T extends User>
{



/**
 * <p>
 * Creates a new user:
 * <ol>
 * <li>
 * Checks whether the row with given email is not already exist in the database
 * </li>
 * <li>
 * Creates a new row in the [users] table in the database by passing generated id and other variables using JSQL-query
 * </li>
 * <li>
 * Changes created row by adding user's roles into it
 * </li>
 * <li>
 * Generates a random verification code for user's registration
 * </li>
 * <li>
 * Creates a new row in [accountverifications] table in the database
 * </li>
 * <li>
 * Sends verification URL to user's email address
 * </li>
 * <li>
 * Makes user's account an enabled one
 * </li>
 * </ol>
 * </p>
 */
T create(T data);



Collection<T> list(int page, int pageSize);



/**
 * <p>
 * Gets an existing row from [users] table in the database using given user's id
 * </p>
 */
T get(Long id);



T update(T data);



Boolean delete(Long id);



/**
 * <p>
 * Gets User from [users] table in the database
 * </p>
 */
User getUserByEmail(String email);



void sendVerificationCode(UserDTO user);



/**
 * <p>
 * Verifies given code for 2-factor authentication:
 * </p>
 * <ol>
 * <li>
 * Checks whether verification code for given user is no expired yet
 * </li>
 * <li>
 * Checks whether verification code is legit
 * </li>
 * <li>
 * Deletes verification code from [code] column in [TwoFactorVerifications] table for given user
 * </li>
 * <li>
 * Returns User
 * </li>
 * </ol>
 */
User verifyCode(String email, String code);



/**
 * <p>
 * Asks UserRepositoryImpl to change a row in the [users] table based on the given email
 * <ol>
 * <li>
 * Set expiration time for URL for changing a user's password
 * </li>
 * <li>
 * Generate a URL for changing the password
 * </li>
 * <li>
 * Deletes previous row that represents URL for changing a password from [resetpasswordverifications] table for given user
 * </li>
 * <li>
 * Create a new row that represents URL for changing a password in [resetpasswordverifications] table for given user
 * </li>
 * <li>
 * Send an email with a URL to reset user's password to user's email
 * </li>
 * </ol>
 * </p>
 */
void resetPassword(String email);



/**
 * <p>
 * Asks UserReopsitoryImpl to:
 * <ol>
 * <li>
 * Checks whether given URL for changing a password was expired
 * </li>
 * <li>
 * Return User
 * </li>
 * </ol>
 * </p>
 */
T verifyPasswordKey(String key);



void renewPassword(String key, String password, String confirmPassword);



/**
 * <p>
 * Asks UserRepositoryImol to:
 * <ol>
 * <li>
 * Check that confirm password equals to original one
 * </li>
 * <li>
 * Change a row in [users] table by changing [password] column value
 * </li>
 * </ol>
 * </p>
 */
void renewPassword(Long userId, String password, String confirmPassword);



/**
 * <p>
 * Asks UserRepositoryImpl to:
 * <ol>
 * <li>
 * Change row in [user] table by set [enabled] column to true
 * </li>
 * <li>
 * Return updated User
 * </li>
 * </ol>
 * </p>
 */
T verifyAccountKey(String key);



T updateUserDetails(UpdateForm user);



/**
 * Asks UserRepositoryImpl to:
 * <ol>
 * <li>Check that new password and duplicate of it is equal
 * <li>Check that old password, provided by user, is equal to password received from database
 * <li>Change row in the [users] table by saving new password to database
 * </ol>
 */
void updatePassword(Long id, String currentPassword, String newPassword, String confirmNewPassword);



void updateAccountSettings(Long userId, Boolean enabled, Boolean notLocked);



User toggleMfa(String email);



void updateImage(UserDTO user, MultipartFile image);
}