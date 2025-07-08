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
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { log_download_file } from "../../util/APIUtils";
import { ACCESS_TOKEN, SA_BASE_URL, API_BASE_URL, ASSINA_CLIENT_BASE_URL } from "../../constants";
import $ from "jquery";
import "smartwizard/dist/css/smart_wizard_all.css";
import smartWizard from "smartwizard";
import LoadingIndicator from "../../common/LoadingIndicator";

import { InitializeStepper, InitPage, nextStep, back } from "./site";

import "./Sign.css";
import { QRCode } from "react-qrcode-logo";
import symbol from "../../img/Symbol.png";

class Sign extends Component {
  componentDidMount() {
    $(function () {
      $("#smartwizard").smartWizard({
        selected: 0, // Initial selected step, 0 = first step
        theme: "square", // theme for the wizard, related css need to include for other than default theme
        justified: true, // Nav menu justification. true/false
        autoAdjustHeight: true, // Automatically adjust content height
        backButtonSupport: true, // Enable the back button support
        enableUrlHash: true, // Enable selection of the step based on url hash
        transition: {
          animation: "slideHorizontal", // Animation effect on navigation, none|fade|slideHorizontal|slideVertical|slideSwing|css(Animation CSS class also need to specify)
          speed: "400", // Animation speed. Not used if animation is 'css'
          easing: "", // Animation easing. Not supported without a jQuery easing plugin. Not used if animation is 'css'
          prefixCss: "", // Only used if animation is 'css'. Animation CSS prefix
          fwdShowCss: "", // Only used if animation is 'css'. Step show Animation CSS on forward direction
          fwdHideCss: "", // Only used if animation is 'css'. Step hide Animation CSS on forward direction
          bckShowCss: "", // Only used if animation is 'css'. Step show Animation CSS on backward direction
          bckHideCss: "", // Only used if animation is 'css'. Step hide Animation CSS on backward direction
        },
        toolbar: {
          position: "bottom", // none|top|bottom|both
          showNextButton: true, // show/hide a Next button
          showPreviousButton: true,
        },
        anchor: {
          enableNavigation: true, // Enable/Disable anchor navigation
          enableNavigationAlways: false, // Activates all anchors clickable always
          enableDoneState: true, // Add done state on visited steps
          markPreviousStepsAsDone: true, // When a step selected by url hash, all previous steps are marked done
          unDoneOnBackNavigation: false, // While navigate back, done state will be cleared
          enableDoneStateNavigation: true, // Enable/Disable the done state navigation
        },
        keyboard: {
          keyNavigation: true, // Enable/Disable keyboard navigation(left and right keys are used if enabled)
          keyLeft: [37], // Left key code
          keyRight: [39], // Right key code
        },
        lang: {
          // Language variables for button
          next: "Next",
          previous: "Previous",
        },
        disabledSteps: [], // Array Steps disabled
        errorSteps: [], // Array Steps error
        warningSteps: [], // Array Steps warning
        hiddenSteps: [], // Hidden steps
        getContent: null, // Callback function for content loading
      });

      // $("#smartwizard").smartWizard("reset");

      // Step show event
      $("#smartwizard").on(
        "showStep",
        function (e, anchorObject, stepIndex, stepDirection, stepPosition) {
          // Get step info from Smart Wizard
          let stepInfo = $("#smartwizard").smartWizard("getStepInfo");
          let totSteps = stepInfo.totalSteps;
          var step_num = stepInfo.currentStep;
          if (step_num === 2 || step_num === 3) {
            $(".sw-btn-next").hide();
            $(".sw-btn-prev").hide();
          } else {
            $(".sw-btn-next").show();
            $(".sw-btn-prev").show();
          }
        }
      );
    });
  }

  constructor(props) {
    super(props);
    this.state = {
      file: "",
      fileName: "",
      fileLink: "",
      credentials: [],
      selectedCredential: "",
      credentialName: "",
      answerFromOID4VP: false,
      visible: false,
      same_device_deeplink: "",
      cross_device_deeplink: "",
    };

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
        if (res.data.length != 0) {
          this.setState({
            credentials: res.data,
          });
        } else {
          <div>{toast.warning("Please create a certificate to proceed")}</div>;
          setTimeout(() => {
            window.location = "/profile";
          }, 3000);
        }
      })
      .catch((error) => {
        console.log(error);
      });

    this.selectCredential = this.selectCredential.bind(this);
    this.onFileChange = this.onFileChange.bind(this);
    this.authorizationWithOID4vP = this.authorizationWithOID4vP.bind(this);
    this.downloadFile = this.downloadFile.bind(this);
  }

  selectCredential = (event, alias) => {
    event.preventDefault();
    const credential = this.state.credentials.find((c) => c.alias === alias);
    if (credential) {
      this.setState({
        selectedCredential: alias,
        credentialName: credential.alias,
      });
      localStorage.setItem("credential", this.state.selectedCredential);
    }
  };

  onFileChange = (event) => {
    this.setState({
      file: event.target.files[0],
      fileName: event.target.files[0].name,
    });
    const file = event.target.files[0];
    const reader = new FileReader();

    reader.onload = (event) => {
      const fileContent = event.target.result;
      localStorage.setItem("file", fileContent);
      localStorage.setItem("fileName", file.name);

      const embedElement = document.getElementById("pdfEmbed");
      embedElement.setAttribute("src", fileContent);
    };

    reader.readAsDataURL(file);
  };

  authorizationWithOID4vP = (event) => {
    event.preventDefault();

    this.setState({
      answerFromOID4VP: true,
    });

    if (this.state.file === "") {
      this.setState({
        answerFromOID4VP: false,
      });
      return <div>{toast.warning("Please select a file")}</div>;
    }

    const headers = {
      Authorization: "Bearer " + localStorage.getItem(ACCESS_TOKEN),
    };

    const data = new FormData();
    data.append("file", this.state.file);
    data.append("credential", this.state.selectedCredential);
    console.log(data);

    let redirect_uri = ASSINA_CLIENT_BASE_URL+"/sign/redirect";
    let url_encoded_redirect_uri = encodeURIComponent(redirect_uri);

    axios
      .get(SA_BASE_URL + "/getOIDRedirectLink?redirect_uri="+url_encoded_redirect_uri, {
        headers: headers,
      })
      .then((res) => {
        const same_device_deeplink = res.data.same_device_link;
        const cross_device_deeplink = res.data.cross_device_link;
        this.setState({
          same_device_deeplink: same_device_deeplink,
          cross_device_deeplink: cross_device_deeplink,
          visible: true,
        });

        axios
          .post(SA_BASE_URL + "/signFile", data, { headers: headers })
          .then((res) => {
            this.setState({
              answerFromOID4VP: false,
              visible: false,
              same_device_deeplink: "",
              cross_device_deeplink: "",
              fileLink: res.data.fileDownloadUri,
            });
            localStorage.setItem("fileLink", res.data.fileDownloadUri);
            console.log(localStorage.getItem("fileLink"));

            $("#smartwizard").smartWizard("goToStep", 3);
          })
          .catch((error) => {
            if (error.response.status === 504) {
              toast.error(
                "It looks like the request timed out. Please give it another try!"
              );
            } else if (error.response.status === 404) {
              toast.error(
                "Oops! It looks like something didn't go as planned. Please try your request again!"
              );
            } else if (error.response.status === 403) {
              toast.error(
                "Oops! It seems you're not authorized to use the certificate. Please check your permissions and try again."
              );
            } else if (error.response.status === 400) {
              toast.error(
                "Oops! It looks like something didn't go as planned. Please try your request again!"
              );
            } else
              toast.error(
                "Oops! It looks like something didn't go as planned. Please try your request again!"
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
          "Oops! It looks like something didn't go as planned. Please try your request again!"
        );
        this.setState({
          answerFromOID4VP: false,
          visible: false,
          same_device_deeplink: "",
          cross_device_deeplink: "",
        });
      });
  };

  downloadFile = (event) => {
    console.log(localStorage.getItem("fileName"));
    console.log(localStorage.getItem("fileLink"));

    event.preventDefault();
    log_download_file(localStorage.getItem("fileName"));
    window.open(localStorage.getItem("fileLink"));
    window.location = "/profile";
  };

  render() {
    return (
      <div className="container">
        <ToastContainer />

        <div className="row" style={{ marginTop: "3em", marginBottom: "2em" }}>
          <div className="col-md-12 text-center">
            <h3>Signing PDF Document</h3>
          </div>
        </div>

        <div className="row mt-1">
          <div className="col-md-12 card shadow">
            <div id="smartwizard">
              <ul className="nav" style={{ marginTop: "15px" }}>
                <li className="nav-item">
                  <a className="nav-link" href="#step-1">
                    <div className="num">1</div>
                    Select Certificate
                  </a>
                </li>
                <li className="nav-item">
                  <a className="nav-link" href="#step-2">
                    <span className="num">2</span>
                    Upload PDF
                  </a>
                </li>
                <li className="nav-item">
                  <a className="nav-link" href="#step-3">
                    <span className="num">3</span>
                    Sign PDF
                  </a>
                </li>
                <li className="nav-item">
                  <a className="nav-link " href="#step-4">
                    <span className="num">4</span>
                    Download signed PDF
                  </a>
                </li>
              </ul>
              <div
                className="tab-content"
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                }}
              >
                <div
                  id="step-1"
                  className="tab-pane"
                  role="tabpanel"
                  aria-labelledby="step-1"
                  style={{ width: "100%" }}
                >
                  <div className="row certificateContainer">
                    <div className="col-md-12">
                      <h4>
                        Selected Certificate: <b>{this.state.credentialName}</b>
                      </h4>
                      <table className="table table-hover">
                        <thead>
                          <tr>
                            <th>Alias</th>
                          </tr>
                        </thead>
                        <tbody>
                          {this.state.credentials.map((c) => {
                            return (
                              <tr
                                key={c.alias}
                                onClick={(e) =>
                                  this.selectCredential(e, c.alias)
                                }
                              >
                                <td>{c.alias}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
                <div
                  id="step-2"
                  className="tab-pane"
                  role="tabpanel"
                  aria-labelledby="step-2"
                  style={{ width: "100%" }}
                >
                  <div className="row">
                    <div className="col-md-12">
                      <div className="row mt-1">
                        <div className="col-md-12">
                          <div className="input-group mb-3">
                            <input
                              type="file"
                              className="form-control"
                              accept=".pdf"
                              id="inputGroupFile02"
                              name="file"
                              onChange={this.onFileChange}
                              required
                            />
                          </div>
                        </div>
                      </div>
                      <div className="row mt-1">
                        <div className="col-md-12">
                          <embed
                            id="pdfEmbed"
                            width="100%"
                            height="500"
                            type="application/pdf"
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div
                  id="step-3"
                  className="tab-pane"
                  role="tabpanel"
                  aria-labelledby="step-3"
                  style={{ width: "100%" }}
                >
                  <div className="row">
                    <div className="col-md-12">
                      <div className="row mt-1">
                        <div className="col-md-12 text-center">
                          <h4>
                            Selected Certificate:{" "}
                            <b>{this.state.credentialName}</b>
                          </h4>
                        </div>
                      </div>
                      <div className="row mt-1">
                        <div className="col-md-12 text-center">
                          <h4>
                            Uploaded PDF File: <b>{this.state.fileName}</b>
                          </h4>
                        </div>
                      </div>
                      <div className="row mt-1">
                        <div className="col-md-12 text-center">
                          <p>
                            The signature will be positioned at the bottom of
                            the last page of the PDF.
                          </p>
                        </div>
                      </div>
                      <div className="row mt-3">
                        <div className="col-md-12 text-center">
                          <button
                            onClick={this.authorizationWithOID4vP}
                            className="btn btn-outline-primary btn-lg"
                            disabled={this.state.answerFromOID4VP}
                          >
                            <h5>
                              Sign PDF with EUDI Wallet
                              <img
                                src="Images/logo.svg"
                                alt="logo"
                                height="30"
                              />
                            </h5>
                          </button>
                          <div className="oid4vp_container">
                            {this.state.answerFromOID4VP &&
                              !this.state.visible && <LoadingIndicator />}

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
                    </div>
                  </div>
                </div>
                <div
                  id="step-4"
                  className="tab-pane"
                  role="tabpanel"
                  aria-labelledby="step-4"
                  style={{ width: "100%" }}
                >
                  <div className="row">
                    <div className="col-md-12">
                      <div className="row mt-1">
                        <div className="col-md-12 text-center">
                          <h3 className="text-success">
                            The PDF file was successfully signed!
                          </h3>
                        </div>
                      </div>
                      <div className="row mt-3">
                        <div className="col-md-12 text-center">
                          <button
                            onClick={this.downloadFile}
                            className="btn btn-outline-success btn-lg"
                          >
                            Download signed PDF{" "}
                            <i className="bi bi-download"></i>{" "}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }
}
export default Sign;
