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

import java.text.SimpleDateFormat;
import java.util.*;

import eu.europa.ec.eudi.signer.rssp.common.config.DataSourceConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import eu.europa.ec.eudi.signer.rssp.api.model.LoggerUtil;
import eu.europa.ec.eudi.signer.rssp.api.payload.LogDTO;
import eu.europa.ec.eudi.signer.rssp.api.services.UserService;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.entities.LogsUser;
import eu.europa.ec.eudi.signer.rssp.entities.User;
import eu.europa.ec.eudi.signer.rssp.repository.EventRepository;
import eu.europa.ec.eudi.signer.rssp.repository.LogsUserRepository;
import eu.europa.ec.eudi.signer.rssp.security.CurrentUser;
import eu.europa.ec.eudi.signer.rssp.security.UserPrincipal;

@RestController
@RequestMapping(value = "/logs")
public class LogsController {
    private static final Logger logger = LoggerFactory.getLogger(LogsController.class);
    private final UserService userService;
    private final LogsUserRepository repository;
    private final Map<Integer, String> events;
    private final SimpleDateFormat formatter;
    private final LoggerUtil loggerUtil;

    public LogsController(@Autowired final LogsUserRepository logsUserRepository, @Autowired UserService userService,
                          @Autowired DataSourceConfig dataSourceConfig, @Autowired LoggerUtil loggerUtil) {
        this.userService = userService;
        this.repository = logsUserRepository;
        this.events = EventRepository.event(dataSourceConfig.getDatasourceUrl(), dataSourceConfig.getDatasourceUsername(), dataSourceConfig.getDatasourcePassword());
        this.formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        this.loggerUtil = loggerUtil;
    }

    /**
     * Function that returns either an empty list if the user is not found, or the
     * list of the logs of the logged-in user.
     * 
     * @param userPrincipal the currentUser logged in
     * @return the list of the logs of the user
     */
    @GetMapping
    public ResponseEntity<List<LogDTO>> getLogsOfUser(@CurrentUser UserPrincipal userPrincipal) {
        String id = userPrincipal.getId();
        Optional<List<LogsUser>> logsOptional = this.repository.findByUsersID(id);

        if (logsOptional.isEmpty()) {
            List<LogDTO> empty = new ArrayList<>();
            return ResponseEntity.ok(empty);
        }

        List<LogDTO> returnList = new ArrayList<>();
        for (LogsUser l : logsOptional.get()) {
            LogDTO lDTO = new LogDTO();
            lDTO.setLogTime(this.formatter.format(l.getLogTime()));
            String success = l.getSuccess() == 0 ? "Failed" : "Success";
            lDTO.setSuccess(success);
            String eventType = this.events.get(l.getEventTypeID());
            lDTO.setEventType(eventType);
            lDTO.setInfo(l.getInfo());
            returnList.add(lDTO);
        }

        returnList.sort(new Comparator<LogDTO>() {
			@Override
			public int compare(LogDTO s1, LogDTO s2) {
				try {
					Date d1 = formatter.parse(s1.getLogTime());
					Date d2 = formatter.parse(s2.getLogTime());
					return d2.compareTo(d1);
				} catch (Exception e) {
					return 0;
				}
			}
		});

        // returnList.sort((o1, o2) -> o2.getLogTime().compareTo(o1.getLogTime()));
        return ResponseEntity.ok(returnList);
    }

    /**
     * Function that allows to add a logout log.
     * Throws an exception if the user is not found.
     * 
     * @param userPrincipal the user that made the request
     * @return a success message
     */
    @GetMapping("/logout")
    public ResponseEntity<String> logout(@CurrentUser UserPrincipal userPrincipal) {
        String id = userPrincipal.getId();

        Optional<User> user = userService.getUserById(id);
        if (user.isEmpty()) {
            String logMessage = SignerError.UserNotFound.getCode() + "(logout in LogsController.class): User not found.";
            logger.error(logMessage);
            return ResponseEntity.badRequest().body(SignerError.UserNotFound.getFormattedMessage());
        }
        loggerUtil.logsUser(1, id, 5, "");
        return ResponseEntity.ok("ok");
    }

    /**
     * Function that allows to add a log of a download.
     * Throws an Exception if the user logged in is not found.
     * 
     * @param userPrincipal the current user logged in.
     * @param fileName      the name of the file to download.
     * @return a success message
     */
    @PostMapping("/download_log")
    public ResponseEntity<String> download_log(@CurrentUser UserPrincipal userPrincipal, @RequestBody String fileName) {
        String id = userPrincipal.getId();

        Optional<User> user = userService.getUserById(id);
        if (user.isEmpty()) {
            String logMessage = SignerError.UserNotFound.getCode() + " (download_log in LogsController.class) User not found.";
            logger.error(logMessage);
            return ResponseEntity.badRequest().body(SignerError.UserNotFound.getFormattedMessage());
        }
        loggerUtil.logsUser(1, id, 7, "File Name: " + fileName);
        return ResponseEntity.ok("ok");
    }
}
