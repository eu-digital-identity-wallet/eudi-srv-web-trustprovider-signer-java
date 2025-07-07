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

import React, { Component } from 'react';

import { log_download_file } from '../../util/APIUtils';
import axios from 'axios';


class Download extends Component {
    constructor(props) {
        super(props);
        console.log(props);
        this.state = {fileLink: ''};

    }

    handleClick(event) {
        log_download_file();
        event.preventDefault();
        axios.get(event.target.href,{}).then(
            response => {
                let a = document.createElement('a');
                var binaryData = [];
                binaryData.push(response.data);
                a.href=window.URL.createObjectURL(new Blob(binaryData, {type: "application/pdf"}));
                a.download = "signed_file.pdf";
                a.click();
            }
        )
    }

    render() {

        return (
            <div className="download-container">
                <div className="container">
                    <a target="_blank" href={this.props.location.state.fileLink}>Download signed pdf</a>
                </div>
            </div>
        );
    }
}

export default Download
