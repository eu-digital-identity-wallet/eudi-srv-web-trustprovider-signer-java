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

import { API_BASE_URL, ACCESS_TOKEN } from "../constants";

const requestLogs = (options) => {
    const headers = new Headers({
        "Content-Type": "application/json",
    });

    if (localStorage.getItem(ACCESS_TOKEN)) {
        headers.append(
            "Authorization",
            "Bearer " + localStorage.getItem(ACCESS_TOKEN)
        );
    }

    const defaults = { headers: headers };
    options = Object.assign({}, defaults, options);

    return fetch(options.url, options).then((response) => {
        if (response.status !== 200) {
            return Promise.reject();
        } else {
            return response.data;
        }
    });
};

export function log_download_file(fileName) {
    return requestLogs({
        url: API_BASE_URL + "/logs/download_log",
        method: "POST",
        body: fileName,
    });
}
