# TrustProvider Signer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

- [TrustProvider Signer](#trustprovider-signer)
  - [Overview](#overview)
    - [Features](#features)
  - [:heavy_exclamation_mark: Disclaimer](#heavy_exclamation_mark-disclaimer)
  - [Prerequisites](#prerequisites)
    - [Database Setup](#database-setup)
    - [.env File Setup](#env-file-setup)
  - [Local Deployment](#local-deployment)
  - [Docker Deployment](#docker-deployment)
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
This service is composed by three main servers:
- APP: a Backend Server that behaves as a CSC specification's RSSP.
- Signature Application (SA): that behaves similarly to the CSC specification's SA.
- Client: a React.js app that works as a server client for the Backend Servers.

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

## Prerequisites

### Database Setup

The current program uses a **MySQL** database. This is required for both local and Docker-based deployments.

1. **Install and Start MySQL**

   The services require a MySQL database. If you're using Ubuntu or a Debian-based system, you can install and start MySQL server with the following commands:

   ```
   sudo apt install mysql-server -y
   sudo systemctl start mysql.service
   ```

2. **Create Database and User**

   After installing MySQL, open the MySQL shell and execute the following commands to create the database and user:

   ```
   CREATE DATABASE {database_name};
   CREATE USER {database_username}@{ip} IDENTIFIED BY {database_password};
   GRANT ALL PRIVILEGES ON {database_name}.* TO {database_username}@{ip};
   ```

   Replace {ip} with the appropriate IP address or hostname of the database, {database_username} with the username of the user you wish to create, {database_password} with the password of the user and {database_name} with the database to be created. If the services and the database run on the same system, use 'localhost' instead of the IP address:

   ```
   CREATE USER {database_username}@'localhost' IDENTIFIED BY {database_password};
   GRANT ALL PRIVILEGES ON {database_name}.* TO {database_username}@'localhost';
   ```

3. **Create tables in the database**

   Additionally, create a table named **'event'** with the following structure:

   ```
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

4. **Alternative: Set up the database using script**

   The script **create_database.sql** is available in the **tools** directory.
   You can replace the '{database_name}', '{database_username}' and '{database_password}' in the script,
   and run the script to create the database, the user and the table.

5. **Configure Environment Variables and Application Settings**

   Lastly, you will need to keep in mind that you will need to add the database variables '{database_name}', '{database_username}' and '{database_password}' to a configuration file.

   For example, you can configure the variables in a .env file (introduced in the next section):

   ```
   SPRING_DATASOURCE_SERVER={database_host_url}
   SPRING_DATASOURCE_DATABASE={database_name}
   SPRING_DATASOURCE_USERNAME={database_username}
   SPRING_DATASOURCE_PASSWORD={database_password}
   ```

   Then, update the application.yml files (in the resource folder in the module app) or the set the required variables in the .env file to point to the database:

   ```
   datasource:
      username: ${SPRING_DATASOURCE_USERNAME}
      password: ${SPRING_DATASOURCE_PASSWORD}
      url: jdbc:mysql://{SPRING_DATASOURCE_SERVER}/{SPRING_DATASOURCE_DATABASE}?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC&useLegacyDatetimeCode=false
      driver-class-name: com.mysql.cj.jdbc.Driver
   ```

   If deploying via Docker, update the value of the variable '{SPRING_DATASOURCE_SERVER}' to 'host.docker.internal:3306/' as the example:

   ```
   datasource:
      url: jdbc:mysql://host.docker.internal:3306/{database_name}?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC&useLegacyDatetimeCode=false
   ```

   Note: Use host.docker.internal if the MySQL server is running on the host machine and the services are containerized.

### .env File Setup

To deploy the TrustProvider Signer, you must create a .env file containing all required environment variables.
This file centralizes configuration details for database access, encryption, and integration with EJBCA and HSM components.
Create a .env file in the root of your project and define the following variables:

```
SPRING_DATASOURCE_SERVER={database_url} # Example: host.docker.internal:3306 or localhost:3306
SPRING_DATASOURCE_DATABASE={database_name}
SPRING_DATASOURCE_USERNAME={database_username}
SPRING_DATASOURCE_PASSWORD={database_password}

AUTH_JWT_TOKEN_SECRET= # the BASE64-encoded signing key for the JWT token generation: used to digitally sign the JWT
AUTH_SAD_TOKEN_SECRET= # the BASE64-encoded signing key for SAD token generation: used to digitally sign the SAD token

ASSINA_SA_BASE_URL= {sa_url}
CSC_BASE_URL= {app_url}/csc/v1
ASSINA_CLIENT_BASE_URL= {client_url}

# --- Secret Key Encryption ---
AUTH_DB_ENCRYPTION_PASSPHRASE= # Passphrase for encrypting secret keys stored in the database
AUTH_DB_ENCRYPTION_SALT=       # Base64-encoded salt used with the passphrase to derive the encryption key

# --- EJBCA Configuration ---
EJBCA_HOST=                # EJBCA service hostname or IP
EJBCA_CLIENT_P12_FILEPATH= # Path to the client .pfx/.p12 certificate file
EJBCA_CLIENT_P12_PASSWORD= # Password for the P12 file
EJBCA_MANAGEMENT_CA=       # Path to the ManagementCA file
EJBCA_CERTIFICATE_PROFILE_NAME= # Name of the certificate profile in EJBCA
EJBCA_END_ENTITY_PROFILE_NAME=  # Name of the end entity profile in EJBCA
EJBCA_USERNAME=            # EJBCA API username
EJBCA_PASSWORD=            # EJBCA API password

# --- HSM / PKCS#11 Configuration ---
JACKNJI11_PKCS11_LIB_PATH= # Path to your PKCS#11 .so library
JACKNJI11_TEST_INITSLOT=   # Initial HSM slot identifier
JACKNJI11_TEST_TESTSLOT=   # Secondary HSM slot identifier
JACKNJI11_TEST_USER_PIN=   # HSM user PIN
JACKNJI11_TEST_SO_PIN=     # HSM security officer PIN
```

## Local Deployment

### Requirements

- Node (nodejs & npm)
- Java: version 16
- Maven

### Configure the App's application.yml

In order to configure the **App** server, you will need to update the _application.yml_ file in the path "server/app/src/main/resources/".

You can either update the next parameters directly in the _application.yml_ file or setting up the variables in the .env file while adding the following lines in the _application.yml_:

```
spring:
    config:
      import: file:.env[.properties]
```

1. **Update the Datasource Configuration**

   Update the following lines in the _application.yml_, with the variables from the [Database Setup](#database-setup):

   ```
      datasource:
       username: ${SPRING_DATASOURCE_USERNAME}
       password: ${SPRING_DATASOURCE_PASSWORD}
       url: jdbc:mysql://${SPRING_DATASOURCE_SERVER}/${SPRING_DATASOURCE_DATABASE}?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC&useLegacyDatetimeCode=false
       driver-class-name: com.mysql.cj.jdbc.Driver
   ```

   Or alternatively, set up the variables in the .env file in the _server_ folder.

2. **Update the JWTs and SADs secrets**

   Replace the variables _AUTH_JWT_TOKEN_SECRET_ and _AUTH_SAD_TOKEN_SECRET_ by a BASE64-encoded signing key for the JWT token generation, which will be used to digitally sign the JWT and
   a BASE64-encoded signing key for SAD token generation for digitally sign the SAD token, respectively.

   ```
   assina:
     type: userAuthentication
     lifetimeMinutes: 600
     secret: ${AUTH_JWT_TOKEN_SECRET}

   ...

   sad:
     type: SAD
     lifetimeMinutes: 5
     secret: ${AUTH_SAD_TOKEN_SECRET}
   ```

   Or alternatively, set up the variables in the .env file in the _server_ folder.

3. **Update the EJBCA Configuration**

   The current implementation makes HTTP requests to an EJBCA server, which serves as a Certificate Authority (CA) for issuing new certificates when an user requests it.
   In this configuration file, you need to provide the necessary values to access the EJBCA server, such as the server address, PFX file path, password, and other endpoint-specific details.
   Additionally, you can define configurations for different countries, specifying the certificate authority name for each country. Adjust the configurations according to your specific setup and requirements.

   Update the following lines in the _application.yml_ in the directory "server/app/src/main/resources/".

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

   Or alternatively, set up the variables in the .env file in the _server_ folder.

4. **Authentication using OpenId4VP**

   This application requires users to authenticate and authorize the signature of documents with Certificates they own through their EUDI Wallet.
   To enable this feature, communication with a backend **Verifier** is necessary. Define the address, URL and the client*id of the Verifier by adding the configuration in \*'application.yml'* located in the folder \_'server/app/src/main/resources'\_:

   ```
   verifier:
      url:
      address:
      client_id:
   ```

   By default, this configuration is set to a backend server based on the code from the github **'eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt'**. Therefore, the default configuration is:

   ```
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

### Configure HSM

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

**Note:** For local deployment, this variables should be set as environment variables and not through the .env file, because Spring Boot doesn't support traditionally .env file.

### Configure Trusted CAs

To validate the vp_token, it is necessary to validate the issuer of the certificate used in the signature in the mdoc. The application validates that the issuer is one of the trusted CAs known.

The trusted CAs' certificate are stored in the folder _'issuersCertificates'_ in _'server'_.

If you wish to update the issuers accepted by the application, add the certificate to the folder _'issuersCertificate'_.

### Configure Signature Application's (SA) application.yml

In order to configure the **SA** server, you will need to update the _application.yml_ file in the path "server/sa/src/main/resources/".

You can either update the next parameters directly in the _application.yml_ file or setting up the variables in the .env file while adding the following lines in the _application.yml_:

```
spring:
    config:
      import: file:.env[.properties]
```

1. **Update App's CSC Url**

   The Signature Application (SA) needs to know the url of the CSC endpoints. The URL can be defined in the following lines from the _application.yml_:

   ```
   rssp:
    cscBaseUrl: ${CSC_BASE_URL}
   ```

   Or alternatively, set up the variables in the .env file in the _server_ folder.

### Running the TrustProvider Signer

After configuring the previously mentioned settings, navigate to the **tools** directory. Here, you'll find several bash scripts that will compile and launch the TrustProvider Signer.
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

Upon executing all the scripts, the client program will be available on port 3000.

## Docker Deployment

You can also deploy the TrustProvider Signer using Docker, either by:

- Pulling the GitHub package image
- Building the image locally

Note: Don't forget to follow the [Prerequisites](#Prerequisites) and configure the database and the .env file.
For more details on environment variables, refer to the Local Deployment sections of each module.

### Requirements

- Docker
- Docker Compose

### Configure docker-compose.yml

We may need to define a volumes for the HSM and EJBCA configuration in the _docker-compose.yml_.

```
volumes:
   - {PATH_TO_HSM_CONFIG_FILES}:/opt/app/config/hsm/
   - {PATH_TO_EJBCA_CONFIG_FILES}:/opt/app/config/ejbca/
```

Replace {PATH_TO_HSM_CONFIG_FILES} and {PATH_TO_EJBCA_CONFIG_FILES} with the actual paths to your configuration files on the host machine.

If you wish to use the pre-built image available on GitHub instead of building the image locally, modify the docker-compose.yml by replacing the build section with an image declaration like so:

```
services:
  trust_provider_signer_server_app:
    image:
    container_name: trust_provider_signer_server_app
    ...
  trust_provider_signer_server_sa:
    image:
    container_name: trust_provider_signer_server_sa
    ...
  trust_provider_signer_client:
    image:
    container_name: trust_provider_signer_client
    ...
```

**Optional**: To avoid port conflicts, change the exposed port:

```
ports:
    - "8082:8082" # Change first 8082 if the port is already used
```

### Build and Run with Docker

From the project root, run:
`docker compose up --build`

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
