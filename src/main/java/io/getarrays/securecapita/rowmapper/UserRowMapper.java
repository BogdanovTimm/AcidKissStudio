package io.getarrays.securecapita.rowmapper;

import io.getarrays.securecapita.domain.User;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 Mapper from SQL output to User java class
 */
public class UserRowMapper implements RowMapper<User> {
    /**
     <p>
     Maps output from SQL to User java class
     </p>
     */
    @Override
    public User mapRow(ResultSet resultSet, int rowNum) throws SQLException {
        return User.builder()
                .id(resultSet.getLong("id"))
                .firstName(resultSet.getString("first_name"))
                .lastName(resultSet.getString("last_name"))
                .email(resultSet.getString("email"))
                .password(resultSet.getString("password"))
                .address(resultSet.getString("address"))
                .phone(resultSet.getString("phone"))
                .title(resultSet.getString("title"))
                .bio(resultSet.getString("bio"))
                .imageUrl(resultSet.getString("image_url"))
                .enabled(resultSet.getBoolean("enabled"))
                .isUsingMfa(resultSet.getBoolean("using_mfa"))
                .isNotLocked(resultSet.getBoolean("non_locked"))
                .createdAt(resultSet.getTimestamp("created_at").toLocalDateTime())
                .build();

    }
}













