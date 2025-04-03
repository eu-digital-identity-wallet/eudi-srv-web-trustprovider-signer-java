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


import $ from "jquery";
import "smartwizard/dist/css/smart_wizard_all.css";
import smartWizard from 'smartwizard';


function SaveProfileInfo()
{
    var givenName = document.getElementById("givenName");
    var familyName = document.getElementById("familyName");
    var dateOfBirth = document.getElementById("dateOfBirth");
    
    var given = false;
    var family = false;
    var date = false;

    // Validate inputs
    if (givenName.value.trim() === "") {
        givenName.classList.add("is-invalid");
        given = false;
    }
    else {
        given = true;
    }

    if (familyName.value.trim() === "") {
        familyName.classList.add("is-invalid");
        family = false;
    }
    else{
        family = true;
    }

    if (dateOfBirth.value.trim() === "") {
        dateOfBirth.classList.add("is-invalid");
        date = false;
    }
    else{
        date = true;
    }

    if(given && family && date)
    {
        $("#error").hide();
        $("#spinner").show();
        $("#saveBtn").hide();
    }
    else {
        
        $("#saveBtn").show();
        $("#error").show();
        $("#spinner").hide();
    }

    
}

export function InitPage(){
    var contentHeight = $("main").height();
    var screenHeight = window.innerHeight;
    if (contentHeight >= screenHeight) {
        $("main").css({ "height": "auto" });
    }
    else {
        $("main").css({ "min-height": "80vh" });
    }
}

export function InitializeStepper()
{
    $('#smartwizard').smartWizard({
        selected: 0, // Initial selected step, 0 = first step
        theme: 'square', // theme for the wizard, related css need to include for other than default theme
        justified: true, // Nav menu justification. true/false
        autoAdjustHeight: true, // Automatically adjust content height
        backButtonSupport: true, // Enable the back button support
        enableUrlHash: true, // Enable selection of the step based on url hash
        transition: {
            animation: 'slideHorizontal', // Animation effect on navigation, none|fade|slideHorizontal|slideVertical|slideSwing|css(Animation CSS class also need to specify)
            speed: '400', // Animation speed. Not used if animation is 'css'
            easing: '', // Animation easing. Not supported without a jQuery easing plugin. Not used if animation is 'css'
            prefixCss: '', // Only used if animation is 'css'. Animation CSS prefix
            fwdShowCss: '', // Only used if animation is 'css'. Step show Animation CSS on forward direction
            fwdHideCss: '', // Only used if animation is 'css'. Step hide Animation CSS on forward direction
            bckShowCss: '', // Only used if animation is 'css'. Step show Animation CSS on backward direction
            bckHideCss: '', // Only used if animation is 'css'. Step hide Animation CSS on backward direction
        },
        toolbar: {
            position: 'bottom', // none|top|bottom|both
            showNextButton: false, // show/hide a Next button
            showPreviousButton: false, // show/hide a Previous button
            extraHtml: `
            <button class="btn btn-secondary shadow" id="back" style="display:none" onClick={back}><i class="bi bi-arrow-left-circle"></i> Back </button>
            <button class="btn btn-info shadow" id="toUpload" style="display:none" onClick={nextStep('upload')}> Upload Document <i class="bi bi-cloud-arrow-up"></i> </button>
            <button class="btn btn-info shadow" id="toSign" style="display:none" onClick={nextStep('sign')}> Sign PDF document <i class="bi bi-vector-pen"></i></button>
            ` // Extra html to show on toolbar
        },
        anchor: {
            enableNavigation: true, // Enable/Disable anchor navigation 
            enableNavigationAlways: false, // Activates all anchors clickable always
            enableDoneState: true, // Add done state on visited steps
            markPreviousStepsAsDone: true, // When a step selected by url hash, all previous steps are marked done
            unDoneOnBackNavigation: false, // While navigate back, done state will be cleared
            enableDoneStateNavigation: true // Enable/Disable the done state navigation
        },
        keyboard: {
            keyNavigation: true, // Enable/Disable keyboard navigation(left and right keys are used if enabled)
            keyLeft: [37], // Left key code
            keyRight: [39] // Right key code
        },
        lang: { // Language variables for button
            next: 'Next',
            previous: 'Previous'
        },
        disabledSteps: [], // Array Steps disabled
        errorSteps: [], // Array Steps error
        warningSteps: [], // Array Steps warning
        hiddenSteps: [], // Hidden steps
        getContent: null // Callback function for content loading
      });

      // $('#smartwizard').smartWizard("reset");
}

export function nextStep(type) {
    console.log(type);
    // let stepInfo = $('#smartwizard').smartWizard("getStepInfo");
    $('#smartwizard').smartWizard("next");

    if (type == "upload") {
        $("#toUpload").hide();
        $("#toSign").show();
    }
    else if (type == "sign") {
        $("#toSign").hide();
        $("#toDownload").show();
    }
    else if (type == "download") {
        $("#toDownload").hide();
    }
}

export function back() {
    $('#smartwizard').smartWizard("prev");
}