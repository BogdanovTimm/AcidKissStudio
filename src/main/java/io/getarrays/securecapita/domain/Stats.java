package io.getarrays.securecapita.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

/**
 Representations of a data on the top of the home page (number of customers, invoices and $$$)
 */
@Setter
@Getter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
//@JsonInclude(NON_DEFAULT) // We disable this beacause if any of these variables will be equal to 0, then it will not be sent back to frontend server
public class Stats {
    private int totalCustomers;
    private int totalInvoices;
    private double totalBilled;
}
