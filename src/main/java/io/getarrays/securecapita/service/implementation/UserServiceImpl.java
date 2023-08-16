package io.getarrays.securecapita.service.implementation;

import io.getarrays.securecapita.domain.Role;
import io.getarrays.securecapita.domain.User;
import io.getarrays.securecapita.dto.UserDTO;
import io.getarrays.securecapita.form.UpdateForm;
import io.getarrays.securecapita.repository.RoleRepository;
import io.getarrays.securecapita.repository.UserRepository;
import io.getarrays.securecapita.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import static io.getarrays.securecapita.dtomapper.UserDTOMapper.fromUser;

/**
 <p>
 Implementation of UserService.
 </p>
 <p>
 It is like a manager that gets missions from Userservice java class instance
 and then tells others what they need to do to accomplish them
 </p>
 */
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository<User> userRepository;
    private final RoleRepository<Role> roleRoleRepository;
    /**
     <p>
     <ol>
     <li>
     Asks UserRepostiroty to:
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
     </ol>
     </li>
     <li>
     Asks UserDTOMapper to create a UserDTO java class instance from returned User java class isntance
     </li>
     <li>
     Returns UserDTO java class instance
     </li>
     </ol>
     </p>
     */
    @Override
    public UserDTO createUser(User user) {
        return mapToUserDTO(userRepository.create(user));
    }
    /**
     <p>
     <ol>
     <li>
     Asks UserRepostiroty to get an existed row from [users] table using given user's email and return created User back
     </li>
     <li>
     Asks UserDTOMapper to create a UserDTO java class instance from returned User java class isntance
     </li>
     <li>
     Returns UserDTO java class instance
     </li>
     </ol>
     </p>
     */
    @Override
    public UserDTO getUserByEmail(String email) {
        return mapToUserDTO(userRepository.getUserByEmail(email));
    }
    /**
     <p>
     Asks UserRepoisitory to:
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
    @Override
    public void sendVerificationCode(UserDTO user) {
        userRepository.sendVerificationCode(user);
    }
    /**
     <p>
     <ol>
     <li>
     Asks UserRepostiroty to add a new verifying code into [code] column in [twofactorverifictaions] table in the database,
     delete an old one
     and return User java class instance
     </li>
     <li>
     Calls this.mapToUserDTO () function to create a UserDTO java class instance from returned User java class instance
     </li>
     <li>
     Returns UserDTO java class instance
     </li>
     </ol>
     </p>
     */
    @Override
    public UserDTO verifyCode(String email, String code) {
        return mapToUserDTO(userRepository.verifyCode(email, code));
    }
    /**
     <p>
     Asks UserRepository to change a row in the [users] table based on the given email
     <ol>
     <li>
     Set expiration time for URL for changing a user's password
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
    @Override
    public void resetPassword(String email) {
        userRepository.resetPassword(email);
    }
    /**
     <p>
     <ol>
     <li>
     Asks UserRepository to:
     </li>
     <ol>
     <li>
     Checks whether URL for changing a password was expired and
     </li>
     <li>
     Return User
     </li>
     </ol>
     <li>
     Asks MapUserDTO to return UserDTO based on given User
     </li>
     </ol>
     </p>
     */
    @Override
    public UserDTO verifyPasswordKey(String key) {
        return mapToUserDTO(userRepository.verifyPasswordKey(key));
    }
    /**
     <p>
     Asks UserRepository to:
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
    @Override
    public void updatePassword(Long userId, String password, String confirmPassword) {
        userRepository.renewPassword(userId, password, confirmPassword);
    }
    /**
     <p>
     <ol>
     <li>
     Asks UserRepository to:
     <ol>
     <li>
     Change row in [user] table by set [enabled] column to true
     </li>
     <li>
     Return updated User
     </li>
     </ol>
     </li>
     <li>
     Calls this.mapToUserDTO () to return UserDTO java class instance with user's roles
     </li>
     </ol>
     </p>
     */
    @Override
    public UserDTO verifyAccountKey(String key) {
        return mapToUserDTO(userRepository.verifyAccountKey(key));
    }

    @Override
    public UserDTO updateUserDetails(UpdateForm user) {
        return mapToUserDTO(userRepository.updateUserDetails(user));
    }
    /**
     <p>
     <ol>
     <li>
     Asks UserRepostiroty to get an existed row from [users] table using given user's id and return created User back
     </li>
     <li>
     Asks UserDTOMapper to create a UserDTO java class instance from returned User java class isntance
     </li>
     <li>
     Returns UserDTO java class instance
     </li>
     </ol>
     </p>
     */
    @Override
    public UserDTO getUserById(Long userId) {
        return mapToUserDTO(userRepository.get(userId));
    }
    /**
     Asks UserRepository to:
     <ol>
     <li>Check that new password and duplicate of it is equal
     <li>Check that old password, provided by user, is equal to password received from database
     <li>Change row in the [users] table by saving new password to database
     </ol>
     */
    @Override
    public void updatePassword(Long id, String currentPassword, String newPassword, String confirmNewPassword) {
        userRepository.updatePassword(id, currentPassword, newPassword, confirmNewPassword);
    }

    @Override
    public void updateUserRole(Long userId, String roleName) {
        roleRoleRepository.updateUserRole(userId, roleName);
    }

    @Override
    public void updateAccountSettings(Long userId, Boolean enabled, Boolean notLocked) {
        userRepository.updateAccountSettings(userId, enabled, notLocked);
    }

    @Override
    public UserDTO toggleMfa(String email) {
        return mapToUserDTO(userRepository.toggleMfa(email));
    }

    @Override
    public void updateImage(UserDTO user, MultipartFile image) {
        userRepository.updateImage(user, image);
    }
    /**
     <p>
     <ol>
     <li>
     Asks RoleRepository to get user's roles from [roles] table in the database using id of given User java class instance
     </li>
     <li>
     Asks UserDtoMapper to create a UserDTO java class instance from returned User java class instance
     </li>
     <li>
     Returns UserDTO java class instance
     </li>
     </ol>
     </p>
     */
    private UserDTO mapToUserDTO(User user) {
        return fromUser(user, roleRoleRepository.getRoleByUserId(user.getId()));
    }
}
















