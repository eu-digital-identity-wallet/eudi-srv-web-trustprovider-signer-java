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

package eu.europa.ec.eudi.signer.rssp.api.model;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import eu.europa.ec.eudi.signer.rssp.common.config.DataSourceConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class LoggerUtil {
    private final DataSourceConfig dataSourceConfig;

    public static String desc = "";
    private static final Logger logger = LoggerFactory.getLogger(LoggerUtil.class);

    public LoggerUtil(@Autowired DataSourceConfig dataSourceConfig){
        this.dataSourceConfig = dataSourceConfig;
    }

    public void logsUser(int success, String usersID, int eventTypeID, String info) {
        String url = this.dataSourceConfig.getDatasourceUrl();
        String dbUsername = this.dataSourceConfig.getDatasourceUsername();
        String dbPassword = this.dataSourceConfig.getDatasourcePassword();

        try (Connection connection = DriverManager.getConnection(url, dbUsername, dbPassword)) {
            String sql = "INSERT INTO logs_user (success, usersID, eventTypeID, info) VALUES (?, ?, ?, ?)";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setInt(1, success);
                statement.setString(2, usersID);
                statement.setInt(3, eventTypeID);
                statement.setString(4, info);
                statement.executeUpdate();
            }
        } catch (SQLException e) {
            logger.error(String.valueOf(e));
        }
    }
}
