package io.getarrays.securecapita.repository;

import io.getarrays.securecapita.domain.Role;

import java.util.Collection;

/**
 * @author Junior RT
 * @version 1.0
 * @license Get Arrays, LLC (https://getarrays.io)
 * @since 8/28/2022
 */
public interface RoleRepository<T extends Role> {
    /* Basic CRUD Operations */
    T create(T data);
    Collection<T> list();
    T get(Long id);
    T update(T data);
    Boolean delete(Long id);

    /* More Complex Operations */
    void addRoleToUser(Long userId, String roleName);
    Role getRoleByUserId(Long userId);
    Role getRoleByUserEmail(String email);
    void updateUserRole(Long userId, String roleName);
}
