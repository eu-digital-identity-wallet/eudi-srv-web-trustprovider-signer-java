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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.stereotype.Component;

@Component
// @SessionScope
public class VerifierCreatedVariables {
    private volatile ConcurrentMap<String, VerifierCreatedVariable> allVariables;

    public VerifierCreatedVariables() {
        this.allVariables = new ConcurrentHashMap<>();
    }

    public Map<String, VerifierCreatedVariable> getAllVariables() {
        return this.allVariables;
    }

    public boolean containsUser(String user) {
        return allVariables.containsKey(user);
    }

    public synchronized VerifierCreatedVariable getUsersVerifierCreatedVariable(String user, String deviceFlow, String typeOperation) {
        String key = user+":"+deviceFlow;
        VerifierCreatedVariable vcv = allVariables.get(key);
        if (vcv != null && vcv.getType().equals(typeOperation)) {
            allVariables.remove(key);
            return vcv;
        } else
            return null;
    }

    public synchronized void addUsersVerifierCreatedVariable(String user, String deviceFlow, String typeOperation, String nonce, String presentation_id) {
        String key = user+":"+deviceFlow;
        allVariables.put(key, new VerifierCreatedVariable(typeOperation, nonce, presentation_id));
    }

    public synchronized void removeUsersVerifierCreatedVariable(String user, String deviceFlow, String typeOperation) {
        String key = user+":"+deviceFlow;
        VerifierCreatedVariable vcv = allVariables.get(key);
        if (vcv != null && vcv.getType().equals(typeOperation)) {
            allVariables.remove(key);
        }
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (String key : allVariables.keySet()) {
            sb.append("{ " + key + ": " + allVariables.get(key).getNonce() + " | "
                    + allVariables.get(key).getPresentation_id() + " }\n");
        }
        sb.append("----------------------------------------\n");
        return sb.toString();
    }
}
