package io.getarrays.securecapita.repository.implementation;

import io.getarrays.securecapita.domain.Role;
import io.getarrays.securecapita.domain.User;
import io.getarrays.securecapita.domain.UserPlusItsRoles;
import io.getarrays.securecapita.dto.UserDTO;
import io.getarrays.securecapita.enumeration.VerificationType;
import io.getarrays.securecapita.exception.ApiException;
import io.getarrays.securecapita.form.UpdateForm;
import io.getarrays.securecapita.repository.RoleRepository;
import io.getarrays.securecapita.repository.UserRepository;
import io.getarrays.securecapita.rowmapper.UserRowMapper;
import io.getarrays.securecapita.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static io.getarrays.securecapita.enumeration.RoleType.ROLE_USER;
import static io.getarrays.securecapita.enumeration.VerificationType.ACCOUNT;
import static io.getarrays.securecapita.enumeration.VerificationType.PASSWORD;
import static io.getarrays.securecapita.query.UserQuery.*;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.util.Map.of;
import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.time.DateFormatUtils.format;
import static org.apache.commons.lang3.time.DateUtils.addDays;
import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

/**
 * Directly works with the database.
 * Implements UserDetailsService.
 */
@Repository
@RequiredArgsConstructor
@Slf4j
public class UserRepositoryImpl
                                implements
                                UserRepository<User>,
                                UserDetailsService // For Spring Security authentication to work
{



/**
 * Format for Date in MySQL
 */
private static final String DATE_FORMAT = "yyyy-MM-dd hh:mm:ss";

private final NamedParameterJdbcTemplate jdbc;

private final RoleRepository<Role> roleRepository;

/**
 * Encoder for users' passwords
 */
private final BCryptPasswordEncoder encoder;

private final EmailService emailService;
/**
 * <p>
 * Creates a new user:
 * <ol>
 * <li>
 * Calls this.getEmailCount () to check whether the row with given email is not already exist in the database
 * </li>
 * <li>
 * Creates a new instance of GeneratedKeyHolder java class that represents user's id
 * </li>
 * <li>
 * Calls this.getSqlParameterSource () to transfrom given User into variables that can be insterted into JSQL query
 * </li>
 * <li>
 * Create a new row in the [users] table in the database by passing generated id and other variables using JSQL-query
 * </li>
 * <li>
 * Changes created row by adding user's roles into it
 * </li>
 * <li>
 * Calls this.getVerificationUrl () to generate a random verification URL for user's registration
 * </li>
 * <li>
 * Creates a new row in [accountverifications] table in the database
 * </li>
 * <li>
 * Asks email service to send verification URL to user's email address
 * </li>
 * <li>
 * Makes user's account an enabled one
 * </li>
 * </ol>
 * </p>
 */
@Override
public User create(User user)
{
    if(getEmailCount(user.getEmail().trim().toLowerCase()) > 0)
    {
        throw new ApiException("Email already in use. Please use a different email and try again.");
    }
    try
    {
        KeyHolder holder = new GeneratedKeyHolder(); // Create an id for a user
        SqlParameterSource parameters = getSqlParameterSource(user);
        jdbc.update(INSERT_USER_QUERY, parameters, holder);
        user.setId(requireNonNull(holder.getKey()).longValue());  // Insert generated user's id into its java representation
        roleRepository.addRoleToUser(user.getId(), ROLE_USER.name()); // Ads role to user's java representation
        String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(),
                                                    ACCOUNT.getType()
        ); // Creates verification URL
        jdbc.update(INSERT_ACCOUNT_VERIFICATION_URL_QUERY, // Save URL in verification table
                    of("userId", // variables and values to insert into QUERY: User Id
                       user.getId(),
                       "url", // URL for verification of that User
                       verificationUrl
                    )
        );
        sendEmail(user.getFirstName(), user.getEmail(), verificationUrl, ACCOUNT);
        user.setEnabled(false);
        user.setNotLocked(true);
        System.out.println(verificationUrl);
        return user;
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }
}



@Override
public Collection<User> list(int page, int pageSize)
{
    return null;
}



/**
 * <p>
 * Gets an existing row from [users] table in the database using given user's id
 * </p>
 */
@Override
public User get(Long id)
{
    try
    {
        return jdbc.queryForObject(SELECT_USER_BY_ID_QUERY, of("id", id), new UserRowMapper());
    }catch(EmptyResultDataAccessException exception)
    {
        throw new ApiException("No User found by id: " + id);
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }
}



@Override
public User update(User data)
{
    return null;
}



@Override
public Boolean delete(Long id)
{
    return null;
}



/**
 * <p>
 * Check how many user's with given email exists in [users] table in the database
 * </p>
 */
private Integer getEmailCount(String email)
{
    return jdbc.queryForObject(COUNT_USER_EMAIL_QUERY, of("email", email), Integer.class);
}



/**
 * Overrided function from UserDetailService.
 * Gets a row from User table for given user.
 * Creates UserPlusItsRoles (that implements UserDetails interface) that represents given User + user's roles
 * Returns UserPlusItsRoles object
 */
@Override
public UserDetails loadUserByUsername(String email)
                                                    throws UsernameNotFoundException
{
    User user = getUserByEmail(email);
    if(user == null)
    {
        log.error("User not found in the database");
        throw new UsernameNotFoundException("User not found in the database");
    }else
    {
        log.info("User found in the database: {}", email);
        return new UserPlusItsRoles(user,
                                    roleRepository.getRoleByUserId(user.getId()));
    }
}



/**
 * <p>
 * Gets User from [users] table in the database
 * </p>
 */
@Override
public User getUserByEmail(String email)
{
    try
    {
        User user = jdbc.queryForObject(SELECT_USER_BY_EMAIL_QUERY,
                                        of("email", email),
                                        new UserRowMapper()
        );
        return user;
    }catch(EmptyResultDataAccessException exception)
    { // Exception for SQL GET
        throw new ApiException("No User found by email: " + email);
    }catch(Exception exception)
    { // Every other Error
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }
}



/**
 * <p>
 * Creates and sends verification code for 2-facotr authentication to user's phone via SMS:
 * <ol>
 * <li>
 * Sets expiration date for verification code to 24 hours
 * </li>
 * <li>
 * Generates random 8-letters verification code
 * </li>
 * <li>
 * Deletes old verification code if it exists from [TwoFactorVerifications] table in the database
 * </li>
 * <li>
 * Inserts new verification code into [TwoFactorVerifications] table in the database
 * </li>
 * <li>
 * Asks SmsUtils to send verification code to user's phone as an SMS
 * </li>
 * </ol>
 * </p>
 */
@Override
public void sendVerificationCode(UserDTO user)
{
    String expirationDate = format(addDays(new Date(), 1), DATE_FORMAT); // 24 Hour
    String verificationCode = randomAlphabetic(8).toUpperCase();
    try
    {
        jdbc.update(DELETE_VERIFICATION_CODE_BY_USER_ID, of("id", user.getId()));
        jdbc.update(INSERT_VERIFICATION_CODE_QUERY,
                    of("userId", user.getId(), "code", verificationCode, "expirationDate", expirationDate)
        );
        //sendSMS(user.getPhone(), "From: SecureCapita \nVerification code\n" + verificationCode);
        log.info("Verification Code: {}", verificationCode);
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }
}



/**
 * <p>
 * Verifies given code for 2-factor authentication:
 * </p>
 * <ol>
 * <li>
 * Checks whether verification code for given user is no expired yet
 * </li>
 * <li>
 * Gets User from the [users] table by its reference in [TwoFactorVerifications] table
 * </li>
 * <li>
 * Gets User form [users] table by given user's email
 * </li>
 * <li>
 * Checks whether emails from 2 Users are same
 * </li>
 * <li>
 * Deletes verification code from [code] column in [TwoFactorVerifications] table for given user
 * </li>
 * <li>
 * Returns User
 * </li>
 * </ol>
 */
@Override
public User verifyCode(String email, String code)
{
    if(isVerificationCodeExpired(code))
    {
        throw new ApiException("This code has expired. Please login again.");
    }
    try
    {
        User userByCode = jdbc.queryForObject(SELECT_USER_BY_USER_CODE_QUERY,
                                              of("code", code),
                                              new UserRowMapper()
        );
        User userByEmail = jdbc.queryForObject(SELECT_USER_BY_EMAIL_QUERY,
                                               of("email", email),
                                               new UserRowMapper()
        );
        if(userByCode.getEmail().equalsIgnoreCase(userByEmail.getEmail()))
        {
            jdbc.update(DELETE_CODE, of("code", code));
            return userByCode;
        }else
        {
            throw new ApiException("Code is invalid. Please try again.");
        }
    }catch(EmptyResultDataAccessException exception)
    {
        throw new ApiException("Could not find record");
    }catch(Exception exception)
    {
        throw new ApiException("An error occurred. Please try again.");
    }
}



/**
 * <p>
 * Changes a row in the [users] table based on the given email
 * <ol>
 * <li>
 * Checks whether there is a row in a [users] table with given email
 * </li>
 * <li>
 * Sets expiration time as a String
 * </li>
 * <li>
 * Calls this.getUserByEmail () to get User from [users] table using given email
 * </li>
 * <li>
 * Calls this.getVerificationUrl () to generate a URL for changing the password
 * </li>
 * <li>
 * Deletes row from [resetpasswordverifications] table for given user
 * </li>
 * <li>
 * Create a new row in [resetpasswordverifications] table for given user
 * </li>
 * <li>
 * Calls this.sendEmail () to send an email with a URL to reset user's password to user's email
 * </li>
 * </ol>
 * </p>
 */
@Override
public void resetPassword(String email)
{
    if(getEmailCount(email.trim().toLowerCase()) <= 0)
    {
        throw new ApiException("There is no account for this email address.");
    }
    try
    {
        String expirationDate = format(addDays(new Date(), 1), DATE_FORMAT);
        User user = getUserByEmail(email);
        String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(), PASSWORD.getType());
        jdbc.update(DELETE_PASSWORD_VERIFICATION_BY_USER_ID_QUERY, of("userId", user.getId()));
        jdbc.update(INSERT_PASSWORD_VERIFICATION_QUERY,
                    of("userId", user.getId(), "url", verificationUrl, "expirationDate", expirationDate)
        );
        sendEmail(user.getFirstName(), email, verificationUrl, PASSWORD);
        log.info("Verification URL: {}", verificationUrl);
    }catch(Exception exception)
    {
        throw new ApiException("An error occurred. Please try again.");
    }
}



/**
 * <p>
 * Checks whether URL for changing a password was expired and returns User:
 * <ol>
 * <li>
 * Calls this.isLinkExpired to checks whether given URL for changing a password was expired
 * </li>
 * <li>
 * Returns User by given URL for changing a password
 * </li>
 * </ol>
 * </p>
 */
@Override
public User verifyPasswordKey(String key)
{
    if(isLinkExpired(key, PASSWORD))
    {
        throw new ApiException("This link has expired. Please reset your password again.");
    }
    try
    {
        User user = jdbc.queryForObject(SELECT_USER_BY_PASSWORD_URL_QUERY,
                                        of("url", getVerificationUrl(key, PASSWORD.getType())),
                                        new UserRowMapper()
        );
        //jdbc.update("DELETE_USER_FROM_PASSWORD_VERIFICATION_QUERY", of("id", user.getId())); //Depends on use case / developer or business
        return user;
    }catch(EmptyResultDataAccessException exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("This link is not valid. Please reset your password again.");
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }
}



@Override
public void renewPassword(String key, String password, String confirmPassword)
{
    if(!password.equals(confirmPassword))
    {
        throw new ApiException("Passwords don't match. Please try again.");
    }
    try
    {
        jdbc.update(UPDATE_USER_PASSWORD_BY_URL_QUERY,
                    of("password",
                       encoder.encode(password),
                       "url",
                       getVerificationUrl(key, PASSWORD.getType())
                    )
        );
        jdbc.update(DELETE_VERIFICATION_BY_URL_QUERY, of("url", getVerificationUrl(key, PASSWORD.getType())));
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }
}



/**
 * <p>
 * <ol>
 * <li>
 * Checks that confirm password equals to original one
 * </li>
 * <li>
 * Changes row in [users] table by changing [password] column value
 * </li>
 * </ol>
 * </p>
 */
@Override
public void renewPassword(Long userId, String password, String confirmPassword)
{
    if(!password.equals(confirmPassword))
    {
        throw new ApiException("Passwords don't match. Please try again.");
    }
    try
    {
        jdbc.update(UPDATE_USER_PASSWORD_BY_USER_ID_QUERY,
                    of("id", userId, "password", encoder.encode(password))
        );
        //jdbc.update(DELETE_PASSWORD_VERIFICATION_BY_USER_ID_QUERY, of("userId", userId));
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }
}



/**
 * <p>
 * <ol>
 * <li>
 * Gets user from [users] table in the database using given URL for finishing registration
 * </li>
 * <li>
 * Changes row in [user] table by set [enabled] column to true
 * </li>
 * <li>
 * Returns updated User
 * </li>
 * </ol>
 * </p>
 */
@Override
public User verifyAccountKey(String key)
{
    try
    {
        User user = jdbc.queryForObject(SELECT_USER_BY_ACCOUNT_URL_QUERY,
                                        of("url", getVerificationUrl(key, ACCOUNT.getType())),
                                        new UserRowMapper()
        );
        jdbc.update(UPDATE_USER_ENABLED_QUERY, of("enabled", true, "id", user.getId()));
        // Delete after updating - depends on your requirements
        return user;
    }catch(EmptyResultDataAccessException exception)
    {
        throw new ApiException("This link is not valid.");
    }catch(Exception exception)
    {
        throw new ApiException("An error occurred. Please try again.");
    }
}



@Override
public User updateUserDetails(UpdateForm user)
{
    try
    {
        jdbc.update(UPDATE_USER_DETAILS_QUERY, getUserDetailsSqlParameterSource(user));
        return get(user.getId());
    }catch(EmptyResultDataAccessException exception)
    {
        throw new ApiException("No User found by id: " + user.getId());
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }
}



/**
 * <ol>
 * <li>Checks that new password and duplicate of it is equal
 * <li>Calls this.get () to get an existing row from [users] table in the database using given user's id
 * <li>Checks that old password, provided by user, is equal to password received from database
 * <li>Changes row in the [users] table by saving new password to database
 * </ol>
 */
@Override
public void updatePassword(Long id, String currentPassword, String newPassword, String confirmNewPassword)
{
    if(!newPassword.equals(confirmNewPassword))
    {
        throw new ApiException("Passwords don't match. Please try again.");
    }
    User user = get(id);
    if(encoder.matches(currentPassword, user.getPassword()))
    {
        try
        {
            jdbc.update(UPDATE_USER_PASSWORD_BY_ID_QUERY,
                        Map.of("userId",
                               id,
                               "password",
                               encoder.encode(newPassword)
                        )
            );
        }catch(Exception exception)
        {
            throw new ApiException("An error occurred. Please try again.");
        }
    }else
    {
        throw new ApiException("Incorrect current password. Please try again.");
    }
}



@Override
public void updateAccountSettings(Long userId, Boolean enabled, Boolean notLocked)
{
    try
    {
        jdbc.update(UPDATE_USER_SETTINGS_QUERY, of("userId", userId, "enabled", enabled, "notLocked", notLocked));
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again.");
    }
}



/**
 * Enables/Disables 2-Factor Authorization:
 * <li>Gets user by given email
 * <li>Checks that there is user's phone number in the database (if there is not throws exception)
 */
@Override
public User toggleMfa(String email)
{
    User user = getUserByEmail(email);
    if(isBlank(user.getPhone()))
    {
        throw new ApiException("You need a phone number to change Multi-Factor Authentication");
    }
    user.setUsingMfa(!user.isUsingMfa()); // Pass boolean, that is oppositional to current boolean bout using 2-Factor authorization
    try
    {
        jdbc.update(TOGGLE_USER_MFA_QUERY, of("email", email, "isUsingMfa", user.isUsingMfa()));
        return user;
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("Unable to update Multi-Factor Authentication");
    }
}



@Override
public void updateImage(UserDTO user, MultipartFile image)
{
    String userImageUrl = setUserImageUrl(user.getEmail());
    user.setImageUrl(userImageUrl);
    saveImage(user.getEmail(), image);
    jdbc.update(UPDATE_USER_IMAGE_QUERY, of("imageUrl", userImageUrl, "id", user.getId()));
}



/**
 * Creates a new thread to send an email
 */
private void sendEmail(String firstName,
                       String email,
                       String verificationUrl,
                       VerificationType verificationType
)
{
    CompletableFuture.runAsync(()->emailService.sendVerificationEmail(firstName,
                                                                      email,
                                                                      verificationUrl,
                                                                      verificationType
    )
    );
}



private String setUserImageUrl(String email)
{
    return fromCurrentContextPath().path("/api/v1/user/image/" + email + ".png").toUriString();
}



private void saveImage(String email, MultipartFile image)
{
    Path fileStorageLocation = Paths.get(System.getProperty("user.home") + "/Downloads/images/")
                                    .toAbsolutePath()
                                    .normalize();
    if(!Files.exists(fileStorageLocation))
    {
        try
        {
            Files.createDirectories(fileStorageLocation);
        }catch(Exception exception)
        {
            log.error(exception.getMessage());
            throw new ApiException("Unable to create directories to save image");
        }
        log.info("Created directories: {}", fileStorageLocation);
    }
    try
    {
        Files.copy(image.getInputStream(), fileStorageLocation.resolve(email + ".png"), REPLACE_EXISTING);
    }catch(IOException exception)
    {
        log.error(exception.getMessage());
        throw new ApiException(exception.getMessage());
    }
    log.info("File saved in: {} folder", fileStorageLocation);
}



/**
 * Checks whether given URL for changing a password was expired
 */
private Boolean isLinkExpired(String key, VerificationType password)
{
    try
    {
        return jdbc.queryForObject(SELECT_EXPIRATION_BY_URL,
                                   of("url", getVerificationUrl(key, password.getType())),
                                   Boolean.class
        );
    }catch(EmptyResultDataAccessException exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("This link is not valid. Please reset your password again");
    }catch(Exception exception)
    {
        log.error(exception.getMessage());
        throw new ApiException("An error occurred. Please try again");
    }
}



/**
 * <p>
 * Checks whether verification code has expired
 * </p>
 */
private Boolean isVerificationCodeExpired(String code)
{
    try
    {
        return jdbc.queryForObject(SELECT_CODE_EXPIRATION_QUERY, of("code", code), Boolean.class);
    }catch(EmptyResultDataAccessException exception)
    {
        throw new ApiException("This code is not valid. Please login again.");
    }catch(Exception exception)
    {
        throw new ApiException("An error occurred. Please try again.");
    }
}



/**
 * Transform given User into variables that can be inserted into JSQL query
 */
private SqlParameterSource getSqlParameterSource(User user)
{
    return new MapSqlParameterSource()
                                      .addValue("firstName", user.getFirstName())
                                      .addValue("lastName", user.getLastName())
                                      .addValue("email", user.getEmail())
                                      .addValue("password", encoder.encode(user.getPassword())); // Encodes user's password
}



private SqlParameterSource getUserDetailsSqlParameterSource(UpdateForm user)
{
    return new MapSqlParameterSource()
                                      .addValue("id", user.getId())
                                      .addValue("firstName", user.getFirstName())
                                      .addValue("lastName", user.getLastName())
                                      .addValue("email", user.getEmail())
                                      .addValue("phone", user.getPhone())
                                      .addValue("address", user.getAddress())
                                      .addValue("title", user.getTitle())
                                      .addValue("bio", user.getBio());
}



/**
 * Generates a registration verification URL
 */
private String getVerificationUrl(String key, // Given random number
                                  String type
) // Given type of action (creation of a new account or change of a password)
{
    return fromCurrentContextPath().path("/api/v1/user/verify/" + type + "/" + key)
                                   .toUriString(); // Creating Verification URL
}
}
