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
import LogsTable from "./LogsTable";
import { ToastContainer } from "react-toastify";
import LoadingIndicator from "../../common/LoadingIndicator";
import axios from "axios";

class Logs extends Component {
    constructor(props) {
        super(props);
        this.state = {
            logs: [],
            loading: true,
        };
    }

    componentDidMount() {
        const headers = {
            Authorization: "Bearer " + localStorage.getItem(ACCESS_TOKEN),
        };

        axios
            .get(API_BASE_URL + "/logs", {
                headers: headers,
            })
            .then((res) => {
                this.setState({
                    logs: res.data,
                    loading: false,
                });
            })
            .catch((error) => {
                toast.error("Error loading logs.");
                this.setState({
                    loading: false,
                });
                console.log(error);
            });
    }

    render() {
        if (this.state.loading) {
            return <LoadingIndicator />;
        } else {
            return (
                <div className="container" style={{ marginTop: "3em" }}>
                    <ToastContainer />
                    <div className="row mt-1 text-center">
                        <div className="col-md-12">
                            <h3>Logs</h3>
                        </div>
                    </div>
                    <LogsTable logs={this.state.logs} />
                </div>
            );
        }
    }
}

export default Logs;
