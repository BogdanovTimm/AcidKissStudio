package io.getarrays.securecapita.dtomapper;

import io.getarrays.securecapita.domain.Role;
import io.getarrays.securecapita.domain.User;
import io.getarrays.securecapita.dto.UserDTO;
import org.springframework.beans.BeanUtils;

/**
 <p>
 Java class for:
 <ul>
 <li>
 creating a UserDTO based on given User
 </li>
 <li>
 creating a User based on given UserDtTO
 </li>
 </ul>
 </p>
 */
public class UserDTOMapper {
    /**
     Creates a UserDTO based on given User
     */
    public static UserDTO fromUser(User user) {
        UserDTO userDTO = new UserDTO();
        BeanUtils.copyProperties(user, userDTO); // Automatically maps variables and their values from [User] to [UserDTO]
        return userDTO;
    }
    /**
     Creates a UserDTO based on given User and its given roles
     */
    public static UserDTO fromUserWithRole(User user, Role role)
    {
        UserDTO userDTO = new UserDTO();
        BeanUtils.copyProperties(user, userDTO);
        userDTO.setRoleName(role.getName());
        userDTO.setPermissions(role.getPermission());
        return userDTO;
    }
    /**
     Creates a User based on given UserDTO
     */
    public static User toUser(UserDTO userDTO) {
        User user = new User();
        BeanUtils.copyProperties(userDTO, user); // Automatically maps variables and their values from [UserDTO] to [User]
        return user;
    }
}

















