/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.rssp.repository;

import java.util.List;
import java.util.Optional;

import jakarta.transaction.Transactional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import eu.europa.ec.eudi.signer.rssp.entities.Credential;

/**
 * Spring Data Repository with paging and sorting support for Credential
 * entities with String identifiers.
 *
 * Notice that there is no implementation of this interface: Spring Data
 * implements it automatically
 * and translates both the inherited CRUD methods and the custom query methods
 * here to underlying
 * JPA queries.
 *
 * The queries are fired against a database that is automatically connected by
 * the
 * mere declaration of a dependency (on H2 in this case) in the root pom.xml.
 */
public interface CredentialRepository extends JpaRepository<Credential, String> {
    /**
     * Find a certificate by Owner.
     * <p>
     * This takes advantage of Spring Data's automatic mapping of method names to
     * queries.
     * Note that it returns a page of results despite there generally being only a
     * single cert.
     *
     * @param owner    owner id
     * @param pageable pagination and query results
     * @return a page of results with a pagination properties
     * @see <a
     *      https://docs.spring.io/spring-data/jpa/docs/current/reference/html/#jpa.query-methods">https://docs.spring.io/spring-data/jpa/docs/current/reference/html/#jpa.query-methods</a>
     */
    Page<Credential> findByOwner(String owner, Pageable pageable);

    List<Credential> findByOwner(String owner);

    Optional<Credential> findByOwnerAndAlias(String owner, String alias);

    @Transactional
    void deleteByOwnerAndAlias(String owner, String alias);

    long countByOwner(String owner);

}
