package io.getarrays.securecapita.query;

/**
 @author Junior RT
 @version 1.0
 @license Get Arrays, LLC (https://getarrays.io)
 @since 5/15/2023 */
public class CustomerQuery
{
    public static final String STATS_QUERY = "SELECT c.total_customers, i.total_invoices, inv.total_billed FROM (SELECT COUNT(*) total_customers FROM customer) c, (SELECT COUNT(*) total_invoices FROM invoice) i, (SELECT ROUND(SUM(total)) total_billed FROM invoice) inv";
}
