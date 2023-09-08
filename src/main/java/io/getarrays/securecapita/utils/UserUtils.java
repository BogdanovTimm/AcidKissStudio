package io.getarrays.securecapita.utils;

import io.getarrays.securecapita.domain.UserPlusItsRoles;
import io.getarrays.securecapita.dto.UserDTO;
import org.springframework.security.core.Authentication;

/**
 * Java class that takes UserDTO from given Authentication
 */
public class UserUtils
{

/**
 * <p>
 * Gets UserDTO from given authentication:
 * <ol>
 * <li>
 * Asks given authentication to get UserPrincipal
 * </li>
 * <li>
 * Asks UserPrincipal to get UserDTO
 * </li>
 * </ol>
 * </p>
 */
public static UserDTO getAuthenticatedUser(Authentication authentication)
{
    return ((UserDTO)authentication.getPrincipal());
}

/**
 * <p>
 * Gets UserDTO from given authentication:
 * <ol>
 * <li>
 * Asks given authentication to get UserPrincipal
 * </li>
 * <li>
 * Asks UserPrincipal to get UserDTO
 * </li>
 * </ol>
 * </p>
 */
/*
public static UserDTO getLoggedInUser(Authentication authentication)
{
    return ((UserPlusItsRoles)authentication.getPrincipal()).getUser();
}
*/
}
