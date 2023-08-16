package io.getarrays.securecapita.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;

/**
 Representations of a data on the top of the home page (number of customers, invoices and $$$)
 */
@Setter
@Getter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
//@JsonInclude(NON_DEFAULT) // We disable this beacause if either of these variables = 0, then it will not be sent back to frontend server
public class Stats {
    private int totalCustomers;
    private int totalInvoices;
    private double totalBilled;
}
