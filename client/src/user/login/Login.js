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
import "./Login.css";
import LoadingIndicator from "../../common/LoadingIndicator";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { ASSINA_CLIENT_BASE_URL, ASSINA_RSSP_BASE_URL, API_BASE_URL } from "../../constants";
import axios from "axios";
import logo from "../../img/logo.svg";
import { QRCode } from "react-qrcode-logo";
import symbol from "../../img/Symbol.png";
import "bootstrap/dist/css/bootstrap.min.css";
import "../../site.css";
import "./Login.css";

import { AuthContext } from "../../common/AuthProviderFunction";

class Login extends Component {
    render() {
        return (
            <div className="container-fluid p-0">
                <ToastContainer />
                <div className="row w-100 h-100 m-0">
                    <div
                        className="col-md-7 d-flex justify-content-center align-items-center"
                        id="formCol"
                        style={{ height: "100vh", width: "100vw" }}
                    >
                        <div className="login-form row">
                            <div className="col-md-12">
                                <div className="row">
                                    <div className="col-md-12 text-center">
                                        <img
                                            src={logo}
                                            className="img-fluid mt-2 mb-2"
                                            width="150"
                                            alt="logo of EUDIW"
                                        />
                                    </div>
                                </div>
                                <SocialLogin />
                            </div>
                        </div>
                    </div>
                    <div className="col-md-5 p-0 login-image">
                        <div className="h-100"></div>
                    </div>
                </div>
            </div>
        );
    }
}

class SocialLogin extends Component {
    static contextType = AuthContext;

    constructor(props) {
        super(props);
        this.state = { answerFromOID4VP: false, visible: false, same_device_deeplink: "", cross_device_deeplink: "" };
        this.handleClick = this.handleClick.bind(this);
        this.updateStateAfterAuthentication =
            this.updateStateAfterAuthentication.bind(this);
    }

    updateStateAfterAuthentication() {
        this.setState({
            answerFromOID4VP: false,
            visible: false,
            same_device_deeplink: "",
            cross_device_deeplink: "",
        });
    }

    handleClick() {
        this.setState({
            answerFromOID4VP: true,
        });

        let redirect_uri = ASSINA_CLIENT_BASE_URL+"/redirect";
        let url_encoded_redirect_uri = encodeURIComponent(redirect_uri);

        axios
            .get(ASSINA_RSSP_BASE_URL + "/auth/link?redirect_uri="+url_encoded_redirect_uri, { withCredentials: true })
            .then((responseRedirectLink) => {
                const same_device_deeplink = responseRedirectLink.data.same_device_link;
                const cross_device_deeplink = responseRedirectLink.data.cross_device_link;
                this.setState({
                    same_device_deeplink: same_device_deeplink,
                    cross_device_deeplink: cross_device_deeplink,
                    visible: true,
                });

                axios
                    .get(ASSINA_RSSP_BASE_URL + "/auth/token", {
                        withCredentials: true,
                    })
                    .then((responseAutheticationToken) => {
                        const headers = {
                            "Content-Type": "application/json",
                            Authorization:
                                "Bearer " +
                                responseAutheticationToken.data.accessToken,
                        };
                        axios
                            .get(API_BASE_URL + "/user/me", {
                                headers: headers,
                            })
                            .then((res) => {
                                const auth = this.context;
                                auth.loginAction(
                                    res.data.name,
                                    responseAutheticationToken.data.accessToken
                                );
                                this.updateStateAfterAuthentication();
                                toast.success("You're successfully logged in!");
                            })
                            .catch((error) => {
                                console.log(error);
                                this.updateStateAfterAuthentication();
                            });
                    })
                    .catch((error) => {
                        console.log(error);
                        if (error.response.status === 504) {
                            toast.error(
                                "It looks like the request timed out. Please give it another try!"
                            );
                        } else if (error.response.status === 404) {
                            toast.error(
                                "Oops! It looks like something didn't go as planned. Please try your request again! (" +
                                    error.response.data +
                                    ")"
                            );
                        } else if (error.response.status === 400) {
                            toast.error(
                                "Oops! It looks like something didn't go as planned. Please try your request again! (" +
                                    error.response.data +
                                    ")"
                            );
                        } else
                            toast.error(
                                "Oops! It looks like something didn't go as planned. Please try your request again! (" +
                                    error.response.data +
                                    ")"
                            );
                        this.setState({
                            answerFromOID4VP: false,
                            visible: false,
                            same_device_deeplink: "",
                            cross_device_deeplink: "",
                        });
                    });
            })
            .catch((error) => {
                toast.error(
                    "Oops! It looks like something didn't go as planned. Please try your request again! (" +
                        error.response.data +
                        ")"
                );
                this.updateStateAfterAuthentication();
                console.log(error);
            });
    }

    render() {
        return (
            <div className="row mt-3">
                <div className="col-md-12">
                    <button
                        className="btn btn-outline-primary w-100 mt-3"
                        style={{ borderRadius: "1px" }}
                        onClick={this.handleClick}
                        disabled={this.state.answerFromOID4VP}
                    >
                        PID Authentication
                        <img
                            src={logo}
                            className="img-fluid mt-2 mb-2"
                            width="80"
                            alt="logo of EUDIW"
                        />
                    </button>
                    <div className="oid4vp_container">
                        {this.state.answerFromOID4VP && !this.state.visible && (
                            <LoadingIndicator />
                        )}

                        {this.state.visible && (
                            <div className="qrcode_container">
                                <QRCode
                                    value={this.state.cross_device_deeplink}
                                    size={250}
                                    logoImage={symbol}
                                    logoWidth={200}
                                    logoHeight={139}
                                    logoOpacity={0.4}
                                    qrStyle="dots"
                                />
                                <a
                                    className="btn_redirect"
                                    href={this.state.same_device_deeplink}
                                >
                                    Deep Link to EUDI Wallet (same device)
                                </a>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        );
    }
}

export default Login;
