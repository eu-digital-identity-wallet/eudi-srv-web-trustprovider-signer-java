/*
 Copyright 2025 European Commission

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

import React, { Component, useContext } from "react";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { ASSINA_RSSP_BASE_URL, API_BASE_URL } from "../../constants";
import axios from "axios";
import "bootstrap/dist/css/bootstrap.min.css";
import "../../site.css";

import { AuthContext } from "../../common/AuthProviderFunction";

class Redirect extends Component {
  static contextType = AuthContext;

  constructor(props) {
    super(props);
    this.handleClick = this.handleClick.bind(this);
  }

  handleClick() {
    const params = new URLSearchParams(window.location.search);
    const sessionId = params.get("session_id");
    const responseCode = params.get("response_code");

    axios
      .get(
        ASSINA_RSSP_BASE_URL +
          "/auth/token/same-device?session_id=" +
          sessionId +
          "&response_code=" +
          responseCode,
        {
          withCredentials: true,
        }
      )
      .then((responseAutheticationToken) => {
        const headers = {
          "Content-Type": "application/json",
          Authorization:
            "Bearer " + responseAutheticationToken.data.accessToken,
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
            toast.success("You're successfully logged in!");
          })
          .catch((error) => {
            console.log(error);
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
      });
  }

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
                <div className="row mt-3">
                  <button
                    className="btn btn-outline-primary w-100 mt-3"
                    style={{ borderRadius: "1px" }}
                    onClick={this.handleClick}
                  >
                    Successful Authentication
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default Redirect;
