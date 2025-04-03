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

import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

import LoadingIndicator from "../../common/LoadingIndicator";

class CreateCredentialComponent extends Component {
    constructor(props) {
        super(props);
        this.state = {
            inputAlias: "",
            waitCertificate: false,
        };
        this.handleInputChange = this.handleInputChange.bind(this);
        this.createCredential = this.createCredential.bind(this);
        this.reloadDataComponent = this.reloadDataComponent.bind(this);
    }

    reloadDataComponent() {
        this.setState({
            inputAlias: "",
            waitCertificate: false,
        });
    }

    createCredential(event) {
        event.preventDefault();

        if (this.state.inputAlias === "") {
            this.props.onChangeShowInputFields(false);
            return (
                <div>
                    {toast.warning(
                        "Please introduce an alias for the Certificate."
                    )}
                </div>
            );
        }

        this.setState({ waitCertificate: true });

        const headers = {
            Authorization: "Bearer " + localStorage.getItem(ACCESS_TOKEN),
        };
        const data = new FormData();
        data.append("alias", this.state.inputAlias);
        axios
            .post(API_BASE_URL + "/credentials", data, {
                headers: headers,
            })
            .then((res) => {
                toast.success("A certificate was created.");
                this.reloadDataComponent();
                this.props.onChangeShowInputFields(false);
                this.props.onUpdateCertificateList();
            })
            .catch((error) => {
                toast.error(error.response.data);
                this.reloadDataComponent();
                this.props.onChangeShowInputFields(false);
                this.props.onUpdateCertificateList();
            });
    }

    handleInputChange(event) {
        event.preventDefault();
        this.setState({ inputAlias: event.target.value });
    }

    render() {
        return (
            <div className="col-md-12">
                <div className="input-group mb-3" style={{ paddingTop: "1em" }}>
                    <input
                        type="text"
                        className="form-control"
                        name="alias"
                        placeholder="Certificate's alias"
                        aria-label="Certificate's alias"
                        aria-describedby="basic-addon2"
                        value={this.state.inputAlias}
                        onChange={this.handleInputChange}
                    />
                    <div className="input-group-append">
                        <button
                            onClick={this.createCredential}
                            className="btn btn-outline-secondary"
                            type="button"
                            disabled={this.state.waitCertificate}
                        >
                            Create
                        </button>
                    </div>
                </div>
                {this.state.waitCertificate && <LoadingIndicator />}
            </div>
        );
    }
}

export default CreateCredentialComponent;
