package io.getarrays.securecapita.service;

import io.getarrays.securecapita.domain.Role;

import java.util.Collection;

/**
 * @author Junior RT
 * @version 1.0
 * @license Get Arrays, LLC (https://getarrays.io)
 * @since 12/26/2022
 */
public interface RoleService {
    Role getRoleByUserId(Long id);
    Collection<Role> getRoles();
}
