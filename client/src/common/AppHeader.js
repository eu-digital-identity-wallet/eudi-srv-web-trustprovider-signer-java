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
import { Link, NavLink } from "react-router-dom";
import "./AppHeader.css";

import logo from "../img/logo.svg";
import "bootstrap/dist/css/bootstrap.min.css";
import "../site.css";

import { ACCESS_TOKEN, API_BASE_URL } from "../constants";
import axios from "axios";
import { toast } from "react-toastify";
import { AuthContext } from "./AuthProviderFunction";

class AppHeader extends Component {
    static contextType = AuthContext;

    constructor(props) {
        super(props);

        this.verify = this.verify.bind(this);
    }

    verify() {
        const headers = {
            Authorization: "Bearer " + sessionStorage.getItem(ACCESS_TOKEN),
        };

        axios
            .post(API_BASE_URL + "/credentials/list", {}, { headers: headers })
            .then((res) => {
                if (res.data.length > 0) {
                    window.location = "/sign";
                } else {
                    toast.warning("Please create a certificate to proceed");
                }
            })
            .catch((error) => console.log(error));
    }

    render() {
        const context = this.context;

        if (context.authenticated) {
            return (
                <div className="app-header">
                    <nav
                        className="navbar navbar-expand-lg fixed-top"
                        style={{ color: "white", backgroundColor: "#767676" }}
                    >
                        <div className="container">
                            <div>
                                <NavLink to="/" className="navbar-brand">
                                    {" "}
                                    <img src={logo} alt="Logo" />
                                </NavLink>
                            </div>
                            <button
                                className="navbar-toggler"
                                type="button"
                                data-bs-toggle="collapse"
                                data-bs-target="#navbarNav"
                                aria-controls="navbarNav"
                                aria-expanded="false"
                                aria-label="Toggle navigation"
                            >
                                <span className="navbar-toggler-icon"></span>
                            </button>
                            <div
                                className="collapse navbar-collapse"
                                id="navbarNav"
                            >
                                <ul className="navbar-nav me-auto">
                                    <li className="nav-item">
                                        <NavLink
                                            to="/profile"
                                            className="nav-link active"
                                            aria-current="page"
                                        >
                                            TSPsigner
                                        </NavLink>
                                    </li>
                                    <li className="nav-item">
                                        <NavLink
                                            to="/certificates"
                                            className="nav-link"
                                        >
                                            View Certificates
                                        </NavLink>
                                    </li>
                                    <li className="nav-item">
                                        <a
                                            onClick={this.verify}
                                            onKeyDown={this.verify}
                                            className="nav-link"
                                        >
                                            Signing PDF
                                        </a>
                                    </li>
                                    {/*<li className="nav-item">
                                    <a className="nav-link" href="help.html">Help</a>
                                </li>*/}
                                </ul>
                                <ul className="navbar-nav ml-auto">
                                    <li className="nav-item dropdown">
                                        <a
                                            className="nav-link dropdown-toggle"
                                            href="#"
                                            id="navbarDropdown"
                                            role="button"
                                            data-bs-toggle="dropdown"
                                            aria-expanded="false"
                                        >
                                            {" "}
                                            Account{" "}
                                        </a>
                                        <ul
                                            className="dropdown-menu"
                                            aria-labelledby="navbarDropdown"
                                        >
                                            {/*<li><NavLink to="/edit" className="dropdown-item">View Profile</NavLink></li>*/}
                                            <li>
                                                <NavLink
                                                    to="/logs"
                                                    className="dropdown-item"
                                                >
                                                    View Logs
                                                </NavLink>
                                            </li>
                                            <li>
                                                <hr className="dropdown-divider" />
                                            </li>
                                            <li>
                                                <a
                                                    className="dropdown-item"
                                                    onClick={() =>
                                                        context.logout()
                                                    }
                                                    onKeyDown={() =>
                                                        context.logout()
                                                    }
                                                >
                                                    Logout
                                                </a>
                                            </li>
                                        </ul>
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </nav>
                </div>
            );
        } else
            return (
                <nav
                    className="navbar navbar-expand-lg fixed-top"
                    style={{ color: "white", backgroundColor: "#767676" }}
                >
                    <div className="container">
                        <div>
                            <Link to="/" className="navbar-brand">
                                {" "}
                                <img src={logo} alt="Logo" />
                            </Link>
                        </div>
                        <button
                            className="navbar-toggler"
                            type="button"
                            data-bs-toggle="collapse"
                            data-bs-target="#navbarNav"
                            aria-controls="navbarNav"
                            aria-expanded="false"
                            aria-label="Toggle navigation"
                        >
                            <span className="navbar-toggler-icon"></span>
                        </button>
                        <div
                            className="collapse navbar-collapse"
                            id="navbarNav"
                        >
                            <ul className="navbar-nav me-auto">
                                <li className="nav-item">
                                    <Link
                                        to="/"
                                        className="nav-link active"
                                        aria-current="page"
                                    >
                                        Home
                                    </Link>
                                </li>
                                <li className="nav-item">
                                    <Link to="/login" className="nav-link">
                                        Login
                                    </Link>
                                </li>
                            </ul>
                        </div>
                    </div>
                </nav>
            );
    }
}

export default AppHeader;
