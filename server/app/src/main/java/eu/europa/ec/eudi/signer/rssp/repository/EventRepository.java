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

import java.sql.*;
import java.util.HashMap;
import java.util.Map;

public class EventRepository {
    public static Map<Integer, String> event(String url, String user, String password) {
        HashMap<Integer, String> result = new HashMap<>();
        try (Connection connection = DriverManager.getConnection(url, user, password)) {
            String sql = "SELECT * FROM event";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                try (ResultSet resultSet = statement.executeQuery()) {
                    while (resultSet.next()) {
                        int id = resultSet.getInt("eventTypeID");
                        String eventName = resultSet.getString("eventName");
                        System.out.println("Loading event: eventTypeID: " + id + ", eventName: " + eventName);
                        result.put(id, eventName);
                    }
                }
            }
        } catch (SQLException e) {
            System.out.println(e.getLocalizedMessage());
        }
        return result;
    }

}
