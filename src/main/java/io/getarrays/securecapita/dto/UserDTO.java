package io.getarrays.securecapita.dto;

import lombok.*;

import java.time.LocalDateTime;

/**
 * A part of a User java class instance
 */
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class UserDTO
{

private Long id;

private String firstName;

private String lastName;

private String email;

private String address;

private String phone;

private String title;

private String bio;

private String imageUrl;

private boolean enabled;

private boolean isNotLocked;

/**
 * Did user enable Multi-Factor Authorization?
 */
private boolean isUsingMfa;

private LocalDateTime createdAt;

private String roleName;

private String permissions;
}
