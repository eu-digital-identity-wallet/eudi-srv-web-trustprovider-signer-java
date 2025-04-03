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
import { ACCESS_TOKEN, API_BASE_URL } from "../../constants";
import axios from "axios";
import LogsTable from "../logs/LogsTable";
import CreateCredentialComponent from "../certificates/CreateCertificateComponent";
import { ToastContainer, toast } from "react-toastify";

import { AuthContext } from "../../common/AuthProviderFunction";
import { NavLink } from "react-router-dom";
import LoadingIndicator from "../../common/LoadingIndicator";

class Profile extends Component {
    static contextType = AuthContext;

    constructor(props) {
        super(props);
        this.state = {
            numCredentials: 0,
            token: localStorage.getItem(ACCESS_TOKEN) || "",
            inputAlias: "",
            showInputFields: false,
            verify_Cert: 0,
            loading: true,
            logs: [],
        };
        this.verify = this.verify.bind(this);
        this.handleOnClickToCreateCertificates =
            this.handleOnClickToCreateCertificates.bind(this);
        this.handleChangeShowInputFields =
            this.handleChangeShowInputFields.bind(this);
        this.onUpdateCertificateList = this.onUpdateCertificateList.bind(this);
    }

    componentDidMount() {
        const headers = {
            Authorization: "Bearer " + this.state.token,
        };
        axios
            .post(
                API_BASE_URL + "/credentials/list",
                {},
                {
                    headers: headers,
                }
            )
            .then((res) => {
                this.setState({
                    numCredentials: res.data.length,
                    verify_Cert: res.data.length > 0 ? 0 : 1,
                });

                axios
                    .get(API_BASE_URL + "/logs", {
                        headers: headers,
                    })
                    .then((resLogs) => {
                        this.setState({
                            logs: resLogs.data,
                            loading: false,
                        });
                    })
                    .catch((error) => {
                        this.setState({
                            loading: false,
                        });
                        toast.error("Error loading logs.");
                    });
            })
            .catch((error) => {
                this.setState({
                    loading: false,
                });
                console.log(error);
            });
    }

    onUpdateCertificateList() {
        const headers = {
            Authorization: "Bearer " + this.state.token,
        };
        axios
            .post(
                API_BASE_URL + "/credentials/list",
                {},
                {
                    headers: headers,
                }
            )
            .then((res) => {
                this.setState({
                    numCredentials: res.data.length,
                    verify_Cert: res.data.length > 0 ? 0 : 1,
                });
                axios
                    .get(API_BASE_URL + "/logs", {
                        headers: headers,
                    })
                    .then((res) => {
                        this.setState({
                            logs: res.data,
                        });
                    })
                    .catch((error) => {
                        toast.error("Error loading logs.");
                    });
            })
            .catch((error) => {
                console.log(error);
            });
    }

    verify() {
        if (this.state.verify_Cert === 1) {
            toast.warning("Please create a certificate to proceed");
        } else if (this.state.verify_Cert === 0) {
            window.location = "/sign";
        }
    }

    handleChangeShowInputFields = (newValue) => {
        this.setState({ showInputFields: newValue });
    };

    handleOnClickToCreateCertificates = (event) => {
        event.preventDefault();
        this.setState({
            showInputFields: true,
        });
    };

    render() {
        if (this.state.loading) {
            return <LoadingIndicator />;
        } else {
            const context = this.context;
            return (
                <div className="container" style={{ marginTop: "3em" }}>
                    <ToastContainer />
                    <div className="row mt-1 text-center">
                        <div className="col-md-12">
                            <h3>Name: {context.currentUserName}</h3>
                            <h4>
                                You have {this.state.numCredentials}{" "}
                                certificates
                            </h4>
                        </div>
                    </div>

                    <div className="row mt-3">
                        <div className="col-md-12 text-center">
                            <a
                                onClick={this.handleOnClickToCreateCertificates}
                                className="btn btn-success"
                                id="createCert"
                            >
                                <i className="bi bi-plus-circle"></i>
                                Create Certificate
                            </a>
                            {this.state.showInputFields && (
                                <CreateCredentialComponent
                                    onChangeShowInputFields={
                                        this.handleChangeShowInputFields
                                    }
                                    onUpdateCertificateList={
                                        this.onUpdateCertificateList
                                    }
                                />
                            )}
                            <NavLink
                                to="/certificates"
                                className="btn btn-warning"
                            >
                                <i className="bi bi-eye"></i> View Certificates
                            </NavLink>
                            <a onClick={this.verify} className="btn btn-info">
                                <i className="bi bi-vector-pen"></i> Sign PDF{" "}
                                Document
                            </a>
                        </div>
                    </div>

                    <LogsTable logs={this.state.logs} />
                </div>
            );
        }
    }
}

export default Profile;
