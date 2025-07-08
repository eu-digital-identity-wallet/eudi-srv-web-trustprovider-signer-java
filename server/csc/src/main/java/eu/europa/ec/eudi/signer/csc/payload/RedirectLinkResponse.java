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

package eu.europa.ec.eudi.signer.csc.payload;

public class RedirectLinkResponse {
    private String same_device_link;
    private String cross_device_link;

    public String getSame_device_link() {
        return same_device_link;
    }

    public void setSame_device_link(String same_device_link) {
        this.same_device_link = same_device_link;
    }

    public String getCross_device_link() {
        return cross_device_link;
    }

    public void setCross_device_link(String cross_device_link) {
        this.cross_device_link = cross_device_link;
    }
}