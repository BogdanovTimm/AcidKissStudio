package io.getarrays.securecapita.resource;

import io.getarrays.securecapita.domain.HttpResponse;
import io.getarrays.securecapita.domain.User;
import io.getarrays.securecapita.domain.UserPlusItsRoles;
import io.getarrays.securecapita.dto.UserDTO;
import io.getarrays.securecapita.event.NewUserEvent;
import io.getarrays.securecapita.exception.ApiException;
import io.getarrays.securecapita.form.*;
import io.getarrays.securecapita.provider.TokenProvider;
import io.getarrays.securecapita.service.EventService;
import io.getarrays.securecapita.service.RoleService;
import io.getarrays.securecapita.service.UserService;
import io.getarrays.securecapita.utils.UserUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import static io.getarrays.securecapita.dtomapper.UserDTOMapper.toUser;
import static io.getarrays.securecapita.enumeration.EventType.*;
import static io.getarrays.securecapita.utils.ExceptionUtils.processError;
import static io.getarrays.securecapita.utils.UserUtils.getAuthenticatedUser;
// import static io.getarrays.securecapita.utils.UserUtils.getLoggedInUser;
import static java.time.LocalDateTime.now;
import static java.util.Map.of;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.IMAGE_PNG_VALUE;
import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

/**
 * REST Controller for all web pages under website.com/user URLs
 */
@RestController
@RequestMapping(path = "/api/v1/user")
@RequiredArgsConstructor
public class UserResource
{

private static final String TOKEN_PREFIX = "Bearer ";

private final UserService userService;

private final RoleService roleService;

private final EventService eventService;

private final AuthenticationManager authenticationManager;

private final TokenProvider tokenProvider;

private final HttpServletRequest request;

private final HttpServletResponse response;

/**
 * Class that creates a new NewUserEvent in such a way that NewUserEventListener will know about it
 */
private final ApplicationEventPublisher publisher;

/**
 * <p>
 * Handles POST-HTTP-Request for signing the user in, that is sent to website.com/login:
 * <ol>
 * <li>
 * Checks given user's email and password by calling this.authenticate () function and returns UserDTO if all good
 * </li>
 * <li>
 * Checks whether user uses 2 factor authentication:
 * </li>
 * <ul>
 * <li>
 * if user uses it - calls this.sendVerificationCode to send verification code via SMS to user's phone
 * </li>
 * <li>
 * if user not uses it - calls this.sendResponse () to return user his JWT access and refresh tokens as JSON HTTP-Response
 * </li>
 * </ul>
 * </ol>
 * </p>
 */
@PostMapping("/login")
public ResponseEntity<HttpResponse> login(@RequestBody
/*                                      */@Valid
/*                                      */LoginForm loginForm)
{
    UserDTO user = authenticate(loginForm.getEmail(),
                                loginForm.getPassword());
    return user.isUsingMfa()
    ? sendVerificationCode(user)
    : sendResponse(user);
}

/**
 * <p>
 * Handles POST-HTTP-Request for registering user, that is sent to website.com/register and returns a HTTP-Response:
 * <ol>
 * <li>
 * Maps given JSON variables and their values to User java class
 * </li>
 * <li>
 * Asks UserService to add given User to the database
 * </li>
 * <li>
 * Asks ResponseEntity to create and return JSON variables and their values back to user as HTTP-Response
 * </li>
 * </ol>
 * </p>
 */
@PostMapping("/register")
public ResponseEntity<HttpResponse> saveUser(@RequestBody
/*                                         */@Valid
/*                                         */User user)
                                                        throws InterruptedException
{
    // TimeUnit.SECONDS.sleep (4);
    UserDTO userDto = userService.createUser(user);
    return ResponseEntity.created(getUri())
                         .body(HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .data(of("user", userDto)) // Returns JSON representation of given [UserDto] (it is not needed in real applications)
                                           .message(String.format("User account created for user %s", user.getFirstName()))
                                           .status(CREATED)
                                           .statusCode(CREATED.value())
                                           .build());
}

/**
 * <p>
 * Handles GET-HTTP-Request that asks for user's account information, that is sent to website.com/profile by taking user's information from authentication and returns a HTTP-Response:
 * <ol>
 * <li>
 * CustomAuthorizationFilter filter checks that user has the right properties
 * </li>
 * <li>
 * Takes user's email from authentication information
 * </li>
 * <li>
 * Asks UserService to get User from the database
 * </li>
 * <li>
 * Asks ResponseEntity to create and return JSON variables and their values back to user as HTTP-Response
 * </li>
 * </ol>
 * </p>
 */
@GetMapping("/profile")
public ResponseEntity<HttpResponse> profile(Authentication authentication)
{
    //UserDTO user = userService.getUserByEmail (getAuthenticatedUser (authentication).getEmail ());
    UserDTO user = getAuthenticatedUser(authentication);
    return ResponseEntity.ok()
                         .body(HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .data(of("user",
                                                    user,
                                                    "events",
                                                    eventService.getEventsByUserId(user.getId()),
                                                    "roles",
                                                    roleService.getRoles()
                                           ))
                                           .message("Profile Retrieved")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build()
                         );
}

@PatchMapping("/update")
public ResponseEntity<HttpResponse> updateUser(@RequestBody
@Valid
UpdateForm user
)
{
    UserDTO updatedUser = userService.updateUserDetails(user);
    publisher.publishEvent(new NewUserEvent(updatedUser.getEmail(), PROFILE_UPDATE));
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .data(of("user",
                                                    updatedUser,
                                                    "events",
                                                    eventService.getEventsByUserId(user.getId()),
                                                    "roles",
                                                    roleService.getRoles()
                                           ))
                                           .message("User updated")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}

// START - To reset password when user is not logged in
/**
 * <p>
 * Handles GET-HTTP-Request for authenticate user if he has enabled 2 factor authentication,
 * that is sent to website.com/verify/code/%user_email%/%generated_code% and returns a HTTP-Response:
 * <ol>
 * <li>
 * Maps %user_email% from URL to [email] variable
 * </li>
 * <li>
 * Maps %generated_code% from URL to [code] variable
 * </li>
 * <li>
 * Asks UserService to verify given verifying code by checking [TwoFactorVerifications] tables in the database
 * </li>
 * <li>
 * Asks ResponseEntity to create and return JSON variables and their values back to user as HTTP-Response. 2 of this variables will contain JWT Acess Token and JWT Refresh Token
 * </li>
 * </ol>
 * </p>
 */
@GetMapping("/verify/code/{email}/{code}")
public ResponseEntity<HttpResponse> verifyCode(@PathVariable("email")
String email,
                                               @PathVariable("code")
                                               String code
)
{
    UserDTO user = userService.verifyCode(email, code);
    publisher.publishEvent(new NewUserEvent(user.getEmail(), LOGIN_ATTEMPT_SUCCESS));
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .data(of("user",
                                                    user,
                                                    "access_token",
                                                    tokenProvider.createAccessToken(getUserPrincipal(user)),
                                                    "refresh_token",
                                                    tokenProvider.createRefreshToken(getUserPrincipal(user))
                                           ))
                                           .message("Login Success")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}

/**
 * <p>
 * Handles GET-HTTP-Request when somebody unauthorized asks to change password for some user based on a given email:
 * <ol>
 * <li>
 * Asks a UserService to:
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
 * </li>
 * <li>
 * Asks ResponseEntity to create and return JSON variables and their values back to user as HTTP-Response
 * </li>
 * </ol>
 * </p>
 */
@GetMapping("/resetpassword/{email}")
public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email")
String email)
{
    userService.resetPassword(email);
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .message("Email sent. Please check your email to reset your password.")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}

/**
 * <p>
 * Handles GET-HTTP-Request for URL that verifies account after registration:
 * </p>
 * <ol>
 * <li>
 * Asks UserService to:
 * <ol>
 * <li>
 * Change row in [user] table by set [enabled] column to true
 * </li>
 * <li>
 * Return updated UserDTO with its roles
 * </li>
 * </ol>
 * </li>
 * <li>
 * Asks ResponseEntity to create and return JSON variables and their values back to user as HTTP-Response
 * </li>
 * </ol>
 * </p>
 */
@GetMapping("/verify/account/{key}")
public ResponseEntity<HttpResponse> verifyAccount(@PathVariable("key")
String key)
            throws InterruptedException
{
    // TimeUnit.SECONDS.sleep (3);
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .message(userService.verifyAccountKey(key).isEnabled() ? "Account already verified" : "Account verified")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}

/**
 * <p>
 * Handles GET-HTTP-Request when somebody try to go to URL that changes a password for some user:
 * <ol>
 * <li>
 * Asks UserService to:
 * </li>
 * <ol>
 * <li>
 * Checks whether URL for changing a password was expired
 * </li>
 * <li>
 * Return User
 * </li>
 * <li>
 * Asks MapUserDTO to return UserDTO based on given User
 * </li>
 * </ol>
 * <li>
 * Asks ResponseEntity to create and return JSON variables and their values back to user as HTTP-Response
 * </li>
 * </ol>
 * </p>
 */
@GetMapping("/verify/password/{key}")
public ResponseEntity<HttpResponse> verifyPasswordUrl(@PathVariable("key")
String key)
            throws InterruptedException
{
    // TimeUnit.SECONDS.sleep (3);
    UserDTO user = userService.verifyPasswordKey(key);
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .data(of("user", user))
                                           .message("Please enter a new password")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}

/**
 * <p>
 * Asks UserRepository to:
 * <ol>
 * <li>
 * Asks UserService to:
 * </li>
 * <ol>
 * <li>
 * Check that confirm password equals to original one
 * </li>
 * <li>
 * Change a row in [users] table by changing [password] column value
 * </li>
 * </ol>
 * <li>
 * Asks ResponseEntity to create and return JSON variables and their values back to user as HTTP-Response
 * </li>
 * </ol>
 * </p>
 */
@PutMapping("/new/password")
public ResponseEntity<HttpResponse> resetPasswordWithKey(@RequestBody @Valid
/*                                                     */NewPasswordForm form)
                                                                               throws InterruptedException
{
    // TimeUnit.SECONDS.sleep (3);
    userService.updatePassword(form.getUserId(), form.getPassword(), form.getConfirmPassword());
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .message("Password reset successfully")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}
// END - To reset password when user is not logged in

/**
 * <ol>
 * <li>Asks UserUtils to receive UserDTO of current logged user
 * <li>Asks UserServcie to:
 * <ol>
 * <li>Check that new password and duplicate of it is equal
 * <li>Check that old password, provided by user, is equal to password received from database
 * <li>Change row in the [users] table by saving new password to database
 * </ol>
 * <li>Asks ResponseEntity to create and return JSON variables and their values back to user/frontend server as HTTP-Response
 */
@PatchMapping("/update/password")
public ResponseEntity<HttpResponse> updatePassword(Authentication authentication,
                                                   @RequestBody @Valid
                                                   UpdatePasswordForm form
)
{
    UserDTO userDTO = UserUtils.getAuthenticatedUser(authentication);
    userService.updatePassword(userDTO.getId(),
                               form.getCurrentPassword(),
                               form.getNewPassword(),
                               form.getConfirmNewPassword()
    );
    publisher.publishEvent(new NewUserEvent(userDTO.getEmail(), PASSWORD_UPDATE));
    return ResponseEntity.ok()
                         .body(HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .data(of("user",
                                                    userService.getUserById(userDTO.getId()),
                                                    "events",
                                                    eventService.getEventsByUserId(userDTO.getId()),
                                                    "roles",
                                                    roleService.getRoles()
                                           )
                                           )
                                           .message("Password updated successfully")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}

@PatchMapping("/update/role/{roleName}")
public ResponseEntity<HttpResponse> updateUserRole(Authentication authentication,
                                                   @PathVariable("roleName")
                                                   String roleName
)
{
    UserDTO userDTO = getAuthenticatedUser(authentication);
    userService.updateUserRole(userDTO.getId(), roleName);
    publisher.publishEvent(new NewUserEvent(userDTO.getEmail(), ROLE_UPDATE));
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .data(of("user",
                                                    userService.getUserById(userDTO.getId()),
                                                    "events",
                                                    eventService.getEventsByUserId(userDTO.getId()),
                                                    "roles",
                                                    roleService.getRoles()
                                           ))
                                           .timeStamp(now().toString())
                                           .message("Role updated successfully")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}

/**
 * Updating whether user's account is enabled and non-locked.
 */
@PatchMapping("/update/settings")
public ResponseEntity<HttpResponse> updateAccountSettings(Authentication authentication,
                                                          @RequestBody @Valid
                                                          SettingsForm form
)
{
    UserDTO userDTO = getAuthenticatedUser(authentication);
    userService.updateAccountSettings(userDTO.getId(), form.getEnabled(), form.getNotLocked());
    publisher.publishEvent(new NewUserEvent(userDTO.getEmail(), ACCOUNT_SETTINGS_UPDATE));
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .data(of("user",
                                                    userService.getUserById(userDTO.getId()),
                                                    "events",
                                                    eventService.getEventsByUserId(userDTO.getId()),
                                                    "roles",
                                                    roleService.getRoles()
                                           ))
                                           .timeStamp(now().toString())
                                           .message("Account settings updated successfully")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}

/**
 * Handles enabling 2-Factor authorization by user
 */
@PatchMapping("/togglemfa")
public ResponseEntity<HttpResponse> toggleMfa(Authentication authentication)
                                                                             throws InterruptedException
{
    // TimeUnit.SECONDS.sleep (3);
    UserDTO user = userService.toggleMfa(getAuthenticatedUser(authentication).getEmail());
    publisher.publishEvent(new NewUserEvent(user.getEmail(), MFA_UPDATE));
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .data(of("user",
                                                    user,
                                                    "events",
                                                    eventService.getEventsByUserId(user.getId()),
                                                    "roles",
                                                    roleService.getRoles()
                                           ))
                                           .timeStamp(now().toString())
                                           .message("Multi-Factor Authentication updated")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}

@PatchMapping("/update/image")
public ResponseEntity<HttpResponse> updateProfileImage(Authentication authentication,
                                                       @RequestParam("image")
                                                       MultipartFile image
)
  throws InterruptedException
{
    UserDTO user = getAuthenticatedUser(authentication);
    userService.updateImage(user, image);
    publisher.publishEvent(new NewUserEvent(user.getEmail(), PROFILE_PICTURE_UPDATE));
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .data(of("user",
                                                    userService.getUserById(user.getId()),
                                                    "events",
                                                    eventService.getEventsByUserId(user.getId()),
                                                    "roles",
                                                    roleService.getRoles()
                                           ))
                                           .timeStamp(now().toString())
                                           .message("Profile image updated")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}

@GetMapping(value = "/image/{fileName}",
            produces = IMAGE_PNG_VALUE)
public byte[] getProfileImage(@PathVariable("fileName")
String fileName
)
  throws Exception
{
    return Files.readAllBytes(Paths.get(System.getProperty("user.home") + "/Downloads/images/" + fileName));
}

/**
 * <p>
 * Handles GET-HTTP-Request for requestin a new JWT-Access Token using JWT-Refresh Token:
 * <ol>
 * <li>
 * Runs this.isHeaderAndTokenValid () to:
 * <ol>
 * <li>
 * Check that there is an Authrorization header in HTTP-Request
 * </li>
 * <li>
 * Check that value od the Authorization header starts with given token prefix ("Bearer " in our case)
 * </li>
 * <li>
 * Check that given userId is not null
 * </li>
 * <li>
 * Checks that token is not expired
 * </li>
 * </ol>
 * </li>
 * <li>
 * Deletes given token prefix from the value from the Authorization header
 * </li>
 * <li>
 * Asks UserService to:
 * <ol>
 * <li>
 * Get an existed row from [users] table using given user's id and return created User back
 * </li>
 * <li>
 * Returns UserDTO java class instance
 * </li>
 * </ol>
 * </li>
 * <li>
 * Asks ResponseEntity to create and return JSON variables and their values back to user as HTTP-Response. 2 of this variables will contain JWT Acess Token and JWT Refresh Token
 * </li>
 * </ol>
 * </p>
 */
@GetMapping("/refresh/token")
public ResponseEntity<HttpResponse> refreshToken(HttpServletRequest request)
{
    if(isHeaderAndTokenValid(request))
    {
        String token = request.getHeader(AUTHORIZATION).substring(TOKEN_PREFIX.length()); // Deletes "Bearer "
        UserDTO user = userService.getUserById(tokenProvider.getSubject(token, request));
        return ResponseEntity.ok()
                             .body(
                                   HttpResponse.builder()
                                               .timeStamp(now().toString())
                                               .data(of("user",
                                                        user,
                                                        "access_token",
                                                        tokenProvider.createAccessToken(getUserPrincipal(user)),
                                                        "refresh_token",
                                                        token
                                               ))
                                               .message("Token refreshed")
                                               .status(OK)
                                               .statusCode(OK.value())
                                               .build());
    }else
    {
        return ResponseEntity.badRequest()
                             .body(
                                   HttpResponse.builder()
                                               .timeStamp(now().toString())
                                               .reason("Refresh Token missing or invalid")
                                               .developerMessage("Refresh Token missing or invalid")
                                               .status(BAD_REQUEST)
                                               .statusCode(BAD_REQUEST.value())
                                               .build());
    }
}

/**
 * <p>
 * Checks that JWT-Refresh Token is valid:
 * <ol>
 * <li>
 * Checks that there is an Authrorization header in HTTP-Request
 * </li>
 * <li>
 * Checks that value od the Authorization header starts with given token prefix ("Bearer " in our case)
 * </li>
 * <li>
 * Asks TokenProvider to:
 * <ol>
 * <li>
 * Check that given userId is not null
 * </li>
 * <li>
 * Checks that token is not expired
 * </li>
 * </ol>
 * </li>
 * <li>
 * Returns true if all above is true
 * </li>
 * </ol>
 * </p>
 */
private boolean isHeaderAndTokenValid(HttpServletRequest request)
{
    return request.getHeader(AUTHORIZATION) != null &&
           request.getHeader(AUTHORIZATION).startsWith(TOKEN_PREFIX) &&
           tokenProvider.isTokenValid(
                                      tokenProvider.getSubject(request.getHeader(AUTHORIZATION).substring(TOKEN_PREFIX.length()),
                                                               request
                                      ),
                                      request.getHeader(AUTHORIZATION).substring(TOKEN_PREFIX.length())
           );
}

/**
 * <p>
 * Handles all HTTP-Requests that are sent to a page on a wepsite that does not exist and returns a HTTP-Response:
 * <ol>
 * <li>
 * Asks ResponseEntity to create and return JSON variables and their values back to user as HTTP-Response
 * </li>
 * </ol>
 * </p>
 */
@RequestMapping("/error")
public ResponseEntity<HttpResponse> handleError(HttpServletRequest request)
{
    return ResponseEntity.badRequest()
                         .body(
                               HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .reason("There is no mapping for a " +
                                                   request.getMethod() +
                                                   " request for this path on the server")
                                           .status(BAD_REQUEST)
                                           .statusCode(BAD_REQUEST.value())
                                           .build());
}

/*
@RequestMapping("/error")
public ResponseEntity<HttpResponse> handleError(HttpServletRequest request) {
    return new ResponseEntity<>(HttpResponse.builder()
            .timeStamp(now().toString())
            .reason("There is no mapping for a " + request.getMethod() + " request for this path on the server")
            .status(NOT_FOUND)
            .statusCode(NOT_FOUND.value())
            .build(), NOT_FOUND);
}
*/

/**
 * Checks given user's email and password and returns UserDTO if all good:
 * <ol>
 * <li>Safes login attempt
 * <li>Asks Authentication Manager to call UserRepostiory.loadByUsername () to create AuthenticationToken (not to be confused with JWT-Access and JWT-Refresh tokens)
 * <li>Returns UserDTO with its Role from AuthenticationToken
 */
private UserDTO authenticate(String email, String password)
{
    UserDTO userDTO = userService.getUserByEmail(email); // It is needed only to safe login attempt
    try
    {
        if(null != userDTO)
        {
            publisher.publishEvent(new NewUserEvent(email, LOGIN_ATTEMPT));
        }
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password)); // Calls UserRepositoryImpl.loadUserByUsername()
        UserDTO userDTOFPlusItsRolesFomAuthenticationToken = ((UserPlusItsRoles)authentication.getPrincipal()).getUserDTOPlusItsRole();
        if(!userDTOFPlusItsRolesFomAuthenticationToken.isUsingMfa())
        {
            publisher.publishEvent(new NewUserEvent(email, LOGIN_ATTEMPT_SUCCESS));
        }
        return userDTOFPlusItsRolesFomAuthenticationToken;
    }catch(Exception exception)
    {
        if(null != userDTO)
        {
            publisher.publishEvent(new NewUserEvent(email, LOGIN_ATTEMPT_FAILURE));
        }
        processError(request, response, exception);
        throw new ApiException(exception.getMessage());
    }
}

private URI getUri()
{ return URI.create(fromCurrentContextPath().path("/api/v1/user/get/<userId>").toUriString()); }

/**
 * <p>
 * Creates a HTTP-Response as JSON variables back to user. 2 of these variables will be user's JSW-Access token and JWT-Refresh token, created using Auth0 Java-JWT maven repository
 * </p>
 */
private ResponseEntity<HttpResponse> sendResponse(UserDTO user)
{
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .data(of("user", // Returns JSON representation of given [UserDto] (it is not needed in real appolications)
                                                    user,
                                                    "access_token",
                                                    tokenProvider.createAccessToken(getUserPrincipal(user)),
                                                    "refresh_token",
                                                    tokenProvider.createRefreshToken(getUserPrincipal(user))
                                           ))
                                           .message("Login Success")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}


/**
 * Creates UserPrincipal java class instance
 */
private UserPlusItsRoles getUserPrincipal(UserDTO user)
{
    return new UserPlusItsRoles(toUser(userService.getUserByEmail(user.getEmail())),
                                roleService.getRoleByUserId(user.getId())
    );
}

/**
 * <p>
 * Sends verification code to user via SMS
 * <ol>
 * <li>
 * Asks UserService to send verifictaion code to user via SMS
 * </li>
 * <li>
 * Returns an HTTP-Response as JSON code back to user
 * </li>
 * </ol>
 * </p>
 */
private ResponseEntity<HttpResponse> sendVerificationCode(UserDTO user)
{
    userService.sendVerificationCode(user);
    return ResponseEntity.ok()
                         .body(
                               HttpResponse.builder()
                                           .timeStamp(now().toString())
                                           .data(of("user", user)) // Returns JSON representation of given [UserDto]
                                           .message("Verification Code Sent")
                                           .status(OK)
                                           .statusCode(OK.value())
                                           .build());
}
}
