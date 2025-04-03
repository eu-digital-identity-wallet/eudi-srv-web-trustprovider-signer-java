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
import axios from "axios";
import { ACCESS_TOKEN, API_BASE_URL } from "../../constants";
import CreateCredentialComponent from "./CreateCertificateComponent";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

import LoadingIndicator from "../../common/LoadingIndicator";

class Certificates extends Component {
    constructor(props) {
        super(props);

        this.state = {
            credentials: [],
            loading: true,
        };

        this.createNewCredentialHandle =
            this.createNewCredentialHandle.bind(this);
        this.handleChangeShowInputFields =
            this.handleChangeShowInputFields.bind(this);
        this.onUpdateCertificateList = this.onUpdateCertificateList.bind(this);
        this.deleteCredential = this.deleteCredential.bind(this);
    }

    componentDidMount() {
        const headers = {
            Authorization: "Bearer " + localStorage.getItem(ACCESS_TOKEN),
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
                if (res.data.length !== 0) {
                    this.setState({
                        credentials: res.data,
                        loading: false,
                    });
                } else {
                    this.setState({
                        loading: false,
                    });
                }
            })
            .catch((error) => {
                console.log(error);
                this.setState({
                    loading: false,
                });
            });
    }

    createNewCredentialHandle(event) {
        event.preventDefault();
        this.setState({ showInputFields: true });
    }

    handleChangeShowInputFields = (newValue) => {
        this.setState({ showInputFields: newValue });
    };

    onUpdateCertificateList() {
        const headers = {
            Authorization: "Bearer " + localStorage.getItem(ACCESS_TOKEN),
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
                    credentials: res.data,
                });
            })
            .catch((error) => {
                console.log(error);
            });
    }

    deleteCredential(event, credential) {
        event.preventDefault();

        const headers = {
            Authorization: "Bearer " + localStorage.getItem(ACCESS_TOKEN),
        };
        const url = API_BASE_URL + "/credentials/" + credential.alias;
        axios
            .delete(url, { headers: headers }, {})
            .then((_) => {
                toast.success(
                    "The Credential " + credential.alias + " was deleted."
                );
                this.onUpdateCertificateList();
            })
            .catch((_) => {
                toast.error(
                    "The Credential " +
                        credential.alias +
                        " could not be deleted."
                );
            });
    }

    render() {
        if (this.state.loading) {
            return <LoadingIndicator />;
        } else {
            return (
                <div className="container" style={{ marginTop: "1.5em" }}>
                    <ToastContainer />
                    <div className="row mt-1">
                        <div className="col-sm-4">
                            <strong>Certificates</strong>
                        </div>
                        <div className="col-md-8">
                            <a
                                onClick={this.createNewCredentialHandle}
                                className="btn btn-success float-end"
                            >
                                <i className="bi bi-plus-circle"></i> Create new
                                Certificate
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
                        </div>
                    </div>
                    <div className="row certificateContainer card shadow mt-3">
                        <div className="col-md-12">
                            <table className="table">
                                <thead>
                                    <tr>
                                        <th>Certificate Alias</th>
                                        <th>Subject DN</th>
                                        <th>Issuer DN</th>
                                        <th>Valid From</th>
                                        <th>Valid To</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {this.state.credentials.map((c, index) => (
                                        <tr key={index}>
                                            <td>{c.alias}</td>
                                            <td>{c.subjectDN}</td>
                                            <td>{c.issuerDN}</td>
                                            <td>{c.validFrom}</td>
                                            <td>{c.validTo}</td>
                                            <td>
                                                <button
                                                    onClick={(e) =>
                                                        this.deleteCredential(
                                                            e,
                                                            c
                                                        )
                                                    }
                                                    type="button"
                                                    className="btn btn-danger"
                                                >
                                                    <i className="bi bi-trash"></i>
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            );
        }
    }
}

export default Certificates;
