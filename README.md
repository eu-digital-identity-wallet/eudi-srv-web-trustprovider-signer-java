# TrustProvider Signer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

- [TrustProvider Signer](#trustprovider-signer)
  - [Overview](#overview)
    - [Features](#features)
  - [:heavy_exclamation_mark: Disclaimer](#heavy_exclamation_mark-disclaimer)
  - [Configuration](#configuration)
    - [Requirements](#requirements)
    - [Database](#database)
    - [HTTP Requests to EJBCA](#http-requests-to-ejbca)
    - [HSM module](#hsm-module)
    - [Authentication using OpenId4VP](#authentication-using-openid4vp)
  - [Running the TrustProvider Signer](#running-the-trustprovider-signer)
  - [Testing](#testing)
  - [Demo videos](#demo-videos)
  - [How to contribute](#how-to-contribute)
  - [License](#license)
    - [Third-party component licenses](#third-party-component-licenses)
    - [License details](#license-details)

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

## Overview

TrustProvider Signer is a remote signing service provider and client.

### Features

The program implements the following features:

- **Create an Account**: Allows users to create new accounts within the program.
- **Authentication using OpenId4VP**: Enables authentication through OpenId4VP.
- **Create Certificates**: Enables authenticated users to create new certificates and their associated key pairs.
- **Sign Documents**: Allows an authenticated user to digitally sign documents.

## :heavy_exclamation_mark: Disclaimer

The released software is a initial development release version:

- The initial development release is an early endeavor reflecting the efforts of a short timeboxed
  period, and by no means can be considered as the final product.
- The initial development release may be changed substantially over time, might introduce new
  features but also may change or remove existing ones, potentially breaking compatibility with your
  existing code.
- The initial development release is limited in functional scope.
- The initial development release may contain errors or design flaws and other problems that could
  cause system or other failures and data loss.
- The initial development release has reduced security, privacy, availability, and reliability
  standards relative to future releases. This could make the software slower, less reliable, or more
  vulnerable to attacks than mature software.
- The initial development release is not yet comprehensively documented.
- Users of the software must perform sufficient engineering and additional testing in order to
  properly evaluate their application and determine whether any of the open-sourced components is
  suitable for use in that application.
- We strongly recommend not putting this version of the software into production use.
- Only the latest version of the software will be supported

## Configuration

### Requirements

- Node (nodejs & npm)
- Java: version 16
- Maven

### Application-auth.yml

It is required to define an **application-auth.yml** file in the path "server/app/src/main/resources/". This file should follow the pattern:

```
auth:
    datasourceUsername: # the username of a database user, with permissions to update the "assina" database
    datasourcePassword: # the password for the database user, with permissions to update the "assina" database
    jwtTokenSecret: # the BASE64-encoded signing key for the JWT token generation: used to digitally sign the JWT
    sadTokenSecret: # the BASE64-encoded signing key for SAD token generation: used to digitally sign the SAD token
    dbEncryptionPassphrase: # a password to encrypt/decrypt the secret keys before saving them in the database
    dbEncryptionSalt: # a BASE64-encoded value corresponding to the "Salt" required to form the key that will encrypt/decrypt the secret keys before saving them in the database
```

### Database

The current program uses a **MySQL** database.

To run it locally, it is necessary to have a MySQL server running. If you're using Ubuntu or a Debian-based system, you can install and start MySQL with the following commands:

```
sudo apt install mysql-server -y
sudo systemctl start mysql.service
```

After installing MySQL, create a database named **"assina"** and a new user:

```bash
CREATE DATABASE assina;
CREATE USER some_username@ip IDENTIFIED BY some_password;
GRANT ALL PRIVILEGES ON *.* TO some_username@ip;
```

Replace 'ip' with the appropriate IP address or hostname of the RSSP component, 'some_username' with the username of the user you wish to create, and 'some_password' with the password of the user. If the RSSP program and the database run on the same system, use 'localhost' instead of the IP address:

```bash
CREATE USER some_username@'localhost' IDENTIFIED BY some_password;
GRANT ALL PRIVILEGES ON *.* TO some_username@'localhost';
```

Additionally, create a table named **'event'** with the following structure:

```bash
CREATE TABLE event (
    eventTypeID INT AUTO_INCREMENT PRIMARY KEY,
    eventName VARCHAR(40)
);

INSERT INTO event (eventName)
VALUES     ('Certificate Issuance'),
	('Delete a Certificate'),
	('Generate Keypair'),
	('Login'),
	('Logout'),
	('Consent to Sign'),
	('Downloaded a File'),
	("Validated the VP Token's Signature"),
	("Validated the VP Token's Integrity");
```

**Note:** After an update of the code, it may be necessary to re-create the database **assina**, as the content of the tables may change:

```bash
DROP DATABASE assina;
CREATE DATABASE assina;
```

Lastly, don't forget to set the username and the password of the user create in the application-auth.yml.

### HTTP Requests to EJBCA

The current implementation makes HTTP requests to an EJBCA server, which serves as a Certificate Authority (CA) for issuing new certificates when an user requests it.

These HTTP requests are executed using configurations specified in the file **"application-ejbca.yml"**, located at _server/app/src/main/resources_. This file supports configurations for different countries.

```
ejbca:
  # Values required to access the EJBCA:
  cahost: # the address of the EJBCA implementation
  clientP12ArchiveFilepath: # the file path to the pfx file
  clientP12ArchivePassword: # the password of the pfx file
  managementCA: # the filepath of the ManagementCA file

  # Endpoint:
  endpoint: /certificate/pkcs10enroll
  # Values required by the endpoint "/pkcs10enroll":
  certificateProfileName: # the Certificate Profile Name (e.g.: ENDUSER)
  endEntityProfileName: # The End Enity Profile Name (e.g.: EMPTY)
  username: # Username for authentication
  password: # Password for authentication
  includeChain: true

  countries:
    - country: # country code
      certificateAuthorityName: # the certificate authority name for that country
```

In this configuration file, you need to provide the necessary values to access the EJBCA server, such as the server address, PFX file path, password, and other endpoint-specific details. Additionally, you can define configurations for different countries, specifying the certificate authority name for each country. Adjust the configurations according to your specific setup and requirements.

### HSM module

The current implementation uses a _Hardware Secure Module_ to create and use the signature keys.
The library **jacknji11** in *https://github.com/joelhockey/jacknji11* allows to make this requests to an HSM distribution. To use this libraries it is required to define the environmental variables:

```bash
JACKNJI11_PKCS11_LIB_PATH={path_to_so}
JACKNJI11_TEST_TESTSLOT={slot}
JACKNJI11_TEST_INITSLOT={slot}
JACKNJI11_TEST_SO_PIN={user_pin}
JACKNJI11_TEST_USER_PIN={user_pin}
```

This version of the program was tested using the HSM distribution _Utimaco vHSM_.

**Note**: When making the first deployment of this version of the program, if the program was executed before, it is necessary to delete the content of the tables of the database _assina_.

### Authentication using OpenId4VP

This application requires users to authenticate and authorize the signature of documents with Certificates they own through their EUDI Wallet.

To enable this feature, communication with a backend **Verifier** is necessary. Define the address, URL and the client*id of the Verifier by adding the configuration in *'application.yml'_ located in the folder _'server/app/src/main/resources'\_:

```bash
verifier:
  url:
  address:
  client_id:
```

By default, this configuration is set to a backend server based on the code from the github **'eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt'**. Therefore, the default configuration is:

```bash
verifier:
  url: https://dev.verifier-backend.eudiw.dev/ui/presentations
  address: dev.verifier-backend.eudiw.dev
  client_id: x509_san_dns:verifier-backend.eudiw.dev
```

When a user wants to authenticate or sign a document, the server communicates with the Verifier and redirects the user to the EUDI Wallet. The result of this process is vp_tokens. The application then validates the vp_tokens received from the Verifier.

The validation process is based on _'6.5. VP Token Validation'_ from _'OpenID for Verifiable Presentations - draft 20'_ and the section _'9.3.1 Inspection procedure for issuer data authentication'_ from _'ISO/IEC FDIS 18013-5'_.

The validation process implemented follows the following steps:

1. "Determine the number of VPs returned in the VP Token and identify in which VP which requested VC is included, using the Input Descriptor Mapping Object(s) in the Presentation Submission".
2. "Perform the checks on the Credential(s) specific to the Credential Format (i.e., validation of the signature(s) on each VC)":\
   2.1. "Validate the certificate included in the MSO header".\
   2.2. "Verify the digital signature of the IssuerAuth structure using the working_public_key, working_public_key_parameters, and working_public_key_algorithm from the certificate validation" (step 2.1).\
   2.3. "Calculate the digest value for every IssuerSignedItem returned in the DeviceResponse structure and verify that these calculated digests equal the corresponding digest values in the MSO."\
   2.4. "Calculate the digest value for every IssuerSignedItem returned in the DeviceResponse structure and verify that these calculated digests equal the corresponding digest values in the MSO."\
   2.5. "Validate the elements in the ValidityInfo structure, i.e. verify that: the 'signed' date is within the validity period of the certificate in the MSO header, the current timestamp shall be equal or later than the ‘validFrom’ element and the 'validUntil' element shall be equal or later than the current timestamp."
3. "Confirm that the returned Credential(s) meet all criteria sent in the Presentation Definition in the Authorization Request."

**Additional Information**

To validate the vp_token, it is necessary to validate the issuer of the certificate used in the signature in the mdoc. The application validates that the issuer is one of the trusted CAs known.

The trusted CAs' certificate are stored in the folder _'issuersCertificates'_ in _'server'_.

If you wish to update the issuers accepted by the application, add the certificate to the folder _'issuersCertificate'_.

## Running the TrustProvider Signer

After configuring the previously mentioned settings, navigate to the tools directory. Here, you'll find several bash scripts that will compile and launch the TrustProvider Signer.
In the **tools** directory, execute the following commands:

```bash
./runRSSP.sh
./runSA.sh
./runFEND.sh
```

These scripts will install all necessary dependencies to run the entire application and start both the Frontend and Backend applications.

Please note that it's essential to execute 'runRSSP.sh' before 'runSA.sh'. Since the scripts initiate Java programs and occupy the bash, additional bash scripts were developed with 'nohup'.

In the same directory, you'll find additional scripts to deploy the program on a remote machine, where required environment variables are defined:

```bash
./runRSSPnohup.sh
./runSApreprod.sh
./runFENDpreprod.sh
```

Upon executing all the scripts, a React program will be available on port 3000.

## Testing

Please use your PID for testing.

You need to have at least 1 certificate in order to request the signing of a document.

If the signing is successful, you will be redirected to a signing page where you can sign a PDF and download your signed pdf file.

## Demo videos

[Authentication and Certificate Issuance](video/eudiwGenCert_720.mp4)

[Authentication and Certificate Issuance](https://github.com/niscy-eudiw/eudi-srv-web-trustprovider-signer-java/assets/62109899/efe034e8-d663-4585-b23d-df3a4f0a02ad)

[Authentication and PDF File Signing](video/eudiwSignCert_720.mp4)

[Authentication and PDF File Signing](https://github.com/niscy-eudiw/eudi-srv-web-trustprovider-signer-java/assets/62109899/758aba74-3a22-438a-a670-5af53f292a72)

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### Third-party component licenses

See [licenses.md](licenses.md) for details.

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
