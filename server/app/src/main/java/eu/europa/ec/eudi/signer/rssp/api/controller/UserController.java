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

package eu.europa.ec.eudi.signer.rssp.api.controller;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.ec.eudi.signer.rssp.api.payload.UserDTO;
import eu.europa.ec.eudi.signer.rssp.api.services.UserService;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.entities.User;
import eu.europa.ec.eudi.signer.rssp.security.CurrentUser;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;

@RestController
@RequestMapping(value = "/user")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;

    public UserController(@Autowired UserService userService){
        this.userService = userService;
    }

    /**
     * Function that allows to get the hash and full name of the user logged in.
     * Throws an exception if the user is not found.
     * 
     * @param userPrincipal the current user logged in
     * @return the data of the user
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        String userId = userPrincipal.getId();
        String userName = userPrincipal.getName();

        Optional<User> user = userService.getUserById(userId);
        if (user.isEmpty()) {
            String logMessage = SignerError.UserNotFound.getCode()
                    + "(getCurrentUser in UserController.class): User not found.";
            logger.error(logMessage);

            return ResponseEntity.badRequest().body(SignerError.UserNotFound.getFormattedMessage());
        }
        return ResponseEntity.ok(new UserDTO(user.get().getHash(), userName));
    }
}
