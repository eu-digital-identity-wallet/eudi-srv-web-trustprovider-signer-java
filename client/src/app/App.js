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
import { Route, Routes } from "react-router-dom";
import AppHeader from "../common/AppHeader";
import Home from "../home/Home";
import Login from "../user/login/Login";
import Redirect from "../user/redirect_login/Redirect";
import RedirectSign from "../user/redirect_sign/RedirectSign";
import Sign from "../user/sign/Sign";
import Download from "../user/download/Download";
import Profile from "../user/profile/Profile";
import Logs from "../user/logs/Logs";
import Certificates from "../user/certificates/Certificates";
import NotFound from "../common/NotFound";
import LoadingIndicator from "../common/LoadingIndicator";
import { ASSINA_RSSP_BASE_URL, ACCESS_TOKEN, API_BASE_URL } from "../constants";
import PersonalizedRoute from "../common/PersonalizedRoute";
import "./App.css";
import axios from "axios";
import AuthProvider from "../common/AuthProviderFunction";

class App extends Component {
    render() {
        return (
            <AuthProvider>
                <AppHeader />
                <Routes>
                    <Route exact path="/" element={<Home />}></Route>
                    <Route path="/login" element={<Login />}></Route>
                    <Route path="/redirect" element={<Redirect />}></Route>
                    <Route path="/sign/redirect" element={<RedirectSign />}></Route>
                    <Route element={<PersonalizedRoute />}>
                        <Route path="/profile" element={<Profile />} />
                        <Route path="/sign" element={<Sign />} />
                        <Route path="/download" element={<Download />} />
                        <Route path="/logs" element={<Logs />} />
                        <Route
                            path="/certificates"
                            element={<Certificates />}
                        />
                    </Route>
                    <Route component={NotFound}></Route>
                </Routes>
            </AuthProvider>
        );
    }
}

export default App;
