package io.getarrays.securecapita.rowmapper;

import io.getarrays.securecapita.domain.Stats;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Mapper from SQL output to Role java class
 */
public class StatsRowMapper implements RowMapper<Stats> {
    /**
     * <p>
     * Maps output from SQL to User java class
     * </p>
     */
    @Override
    public Stats mapRow(ResultSet resultSet, int rowNum) throws SQLException {
        return Stats.builder()
                .totalCustomers(resultSet.getInt("total_customers"))
                .totalInvoices(resultSet.getInt("total_invoices"))
                .totalBilled(resultSet.getDouble("total_billed"))
                .build();
    }
}
