package io.getarrays.securecapita.service;

import io.getarrays.securecapita.domain.Customer;
import io.getarrays.securecapita.domain.Invoice;
import io.getarrays.securecapita.domain.Stats;
import org.springframework.data.domain.Page;

/**
 * @author Junior RT
 * @version 1.0
 * @license Get Arrays, LLC (https://getarrays.io)
 * @since 5/11/2023
 */
public interface CustomerService {
    // Customer functions
    Customer createCustomer(Customer customer);
    Customer updateCustomer(Customer customer);
    Page<Customer> getCustomers(int page, int size);
    Iterable<Customer> getCustomers();
    Customer getCustomer(Long id);
    Page<Customer> searchCustomers(String name, int page, int size);

    // Invoice functions
    Invoice createInvoice(Invoice invoice);
    Page<Invoice> getInvoices(int page, int size);
    void addInvoiceToCustomer(Long id, Invoice invoice);
    Invoice getInvoice(Long id);
    Stats getStats();
}
