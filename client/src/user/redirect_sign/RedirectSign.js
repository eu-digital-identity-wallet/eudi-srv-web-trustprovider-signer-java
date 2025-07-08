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

import React, { Component, useState, useEffect, useContext } from "react";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { ACCESS_TOKEN, SA_BASE_URL } from "../../constants";
import axios from "axios";
import "bootstrap/dist/css/bootstrap.min.css";
import "../../site.css";
import { AuthContext } from "../../common/AuthProviderFunction";
import { useNavigate } from "react-router-dom";

const RedirectSign = () => {
  const navigate = useNavigate();

  const [file, setFile] = useState(localStorage.getItem("file"));
  const [fileName, setFileName] = useState(localStorage.getItem("fileName"));
  const [selectedCredential, setSelectedCredential] = useState(
    localStorage.getItem("credential")
  );

  const handleClick = () => {
    const params = new URLSearchParams(window.location.search);
    const responseCode = params.get("response_code");

    const headers = {
      Authorization: "Bearer " + localStorage.getItem(ACCESS_TOKEN),
    };

    if (!file || !fileName) {
      toast.error("File data is missing. Please try again.");
      return;
    }

    try {
      const byteCharacters = atob(file.split(",")[1]);
      const byteNumbers = new Array(byteCharacters.length);
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
      }
      const byteArray = new Uint8Array(byteNumbers);
      const fileBlob = new Blob([byteArray], { type: "application/pdf" });

      const restoredFile = new File([fileBlob], fileName, {
        type: "application/pdf",
      });

      const data = new FormData();
      data.append("file", restoredFile);
      data.append("credential", selectedCredential);
      data.append("response_code", responseCode);

      axios
        .post(SA_BASE_URL + "/signFile", data, { headers })
        .then((res) => {
          console.log(res.data.fileDownloadUri);
          localStorage.setItem("fileLink", res.data.fileDownloadUri);
          navigate("/sign#step-4"); // ✅ Navigate to step 4

          // ✅ Ensure jQuery is loaded and SmartWizard is initialized
          setTimeout(() => {
            if (window.$) {
              window.$("#smartwizard").smartWizard("goToStep", 3); // Step 4 (0-based index)
            }
          }, 500); // Delay to ensure SmartWizard is ready
        })
        .catch((error) => {
          console.error(error);
          const status = error.response?.status;
          let errorMessage =
            "Oops! It looks like something didn't go as planned. Please try your request again!";
          if (status === 504) {
            errorMessage =
              "It looks like the request timed out. Please give it another try!";
          } else if (status === 404) {
            errorMessage =
              "Oops! It looks like something didn't go as planned. Please try again!";
          } else if (status === 403) {
            errorMessage =
              "Oops! It seems you're not authorized to use the certificate. Please check your permissions and try again.";
          } else if (status === 400) {
            errorMessage =
              "Oops! Something didn't go as planned. Please try again!";
          }
          toast.error(errorMessage);
        });
    } catch (err) {
      toast.error("Error processing the file. Please try again.");
    }
  };

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
                  onClick={handleClick}
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
};

export default RedirectSign;
