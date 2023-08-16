package io.getarrays.securecapita.rowmapper;

import io.getarrays.securecapita.domain.UserEvent;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * @author Junior RT
 * @version 1.0
 * @license Get Arrays, LLC (https://getarrays.io)
 * @since 3/21/2023
 */

public class UserEventRowMapper implements RowMapper<UserEvent> {
    @Override
    public UserEvent mapRow(ResultSet resultSet, int rowNum) throws SQLException {
        return UserEvent.builder()
                .id(resultSet.getLong("id"))
                .type(resultSet.getString("type"))
                .description(resultSet.getString("description"))
                .device(resultSet.getString("device"))
                .ipAddress(resultSet.getString("ip_address"))
                .createdAt(resultSet.getTimestamp("created_at").toLocalDateTime())
                .build();
    }
}
