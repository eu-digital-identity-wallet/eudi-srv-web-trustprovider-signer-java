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

package eu.europa.ec.eudi.signer.rssp.security.openid4vp;

import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import eu.europa.ec.eudi.signer.rssp.entities.User;
import eu.europa.ec.eudi.signer.rssp.repository.UserRepository;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;

/**
 * Custom user details service for loading the user by username or email during
 * authenticated requests
 */
public class OpenId4VPUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public OpenId4VPUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String hash) throws UsernameNotFoundException {
        String[] n = hash.split(";");
        User user = userRepository.findByHash(n[0])
                .orElseThrow(() -> new UsernameNotFoundException("User not found with hash: ." + n[0]));
        return UserPrincipal.create(user, n[1], n[2]);
    }
}
