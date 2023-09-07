package io.getarrays.securecapita.repository;

import io.getarrays.securecapita.domain.Customer;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;

/**
 * @author Junior RT
 * @version 1.0
 * @license Get Arrays, LLC (https://getarrays.io)
 * @since 5/11/2023
 */
public interface CustomerRepository
                                    extends
                                    PagingAndSortingRepository<Customer, Long>, //
                                    ListCrudRepository<Customer, Long>
{
        Page<Customer> findByNameContaining (String name,
                                             Pageable pageable
        );
}
