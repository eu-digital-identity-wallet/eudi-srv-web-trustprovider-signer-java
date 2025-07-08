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

import React, { Component } from "react";
import { ACCESS_TOKEN } from "../../constants";
import { Navigate } from "react-router-dom";

class OAuth2RedirectHandler extends Component {
    getUrlParameter(name) {
        name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
        var regex = new RegExp("[\\?&]" + name + "=([^&#]*)");

        var results = regex.exec(this.props.location.search);
        return results === null
            ? ""
            : decodeURIComponent(results[1].replace(/\+/g, " "));
    }

    render() {
        const token = this.getUrlParameter("token");
        const error = this.getUrlParameter("error");

        if (token) {
            localStorage.setItem(ACCESS_TOKEN, token);
            return (
                <Navigate
                    to={{
                        pathname: "/profile",
                        state: { from: this.props.location },
                    }}
                />
            );
        } else {
            return (
                <Navigate
                    to={{
                        pathname: "/login",
                        state: {
                            from: this.props.location,
                            error: error,
                        },
                    }}
                />
            );
        }
    }
}

export default OAuth2RedirectHandler;
