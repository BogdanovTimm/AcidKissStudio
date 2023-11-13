package io.getarrays.securecapita.domain;

import io.getarrays.securecapita.dto.UserDTO;
import io.getarrays.securecapita.dtomapper.UserDTOMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

import static io.getarrays.securecapita.dtomapper.UserDTOMapper.fromUserWithRole;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;

/**
 * Java class instance that is created for given User java class instance for dealing with User's authentication
 */
@RequiredArgsConstructor
public class UserPlusItsRoles implements UserDetails
{

private final User user;

private final Role role;



/**
 * Gets permissions from [roles] table in the database
 * for User to which this UserPrincipal is bounded
 */
@Override
public Collection<? extends GrantedAuthority> getAuthorities()
{ return stream(this.role.getPermission().split(",".trim())).map(SimpleGrantedAuthority::new).collect(toList()); }

@Override
public String getPassword()
{ return this.user.getPassword(); }

@Override
public String getUsername()
{ return this.user.getEmail(); }

/**
 * We do not use this function, so it is always true for it not to throw exception.
 * Throws exception if this function returns false.
 */
@Override
public boolean isAccountNonExpired()
{ return true; }

@Override
public boolean isAccountNonLocked()
{ return this.user.isNotLocked(); }

/**
 * We do not use this function, so it is always true for it not to throw exception.
 * Throws exception if this function returns false.
 */
@Override
public boolean isCredentialsNonExpired()
{ return true; }

/**
 * Checks whether user's account is enabled
 */
@Override
public boolean isEnabled()
{ return this.user.isEnabled(); }

/**
 * Asks UserDTOMapper to create a UserDTO with its role, based on User to which this UserPrincipal is bounded
 */
public UserDTO getUserDTOPlusItsRole()
{ return UserDTOMapper.fromUserWithRole(this.user, role); }
}
