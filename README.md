# TrustProvider Signer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

## Table of contents

- [TrustProvider Signer](#trustprovider-signer)
  - [Table of contents](#table-of-contents)
  - [Overview](#overview)
    - [Features](#features)
  - [Disclaimer](#disclaimer)
  - [Prerequisites](#prerequisites)
    - [Database Setup](#database-setup)
    - [(Optional) Configure HSM](#optional-configure-hsm)
    - [(Optional) Configure EJBCA](#optional-configure-ejbca)
    - [.env File Setup](#env-file-setup)
  - [Local Deployment](#local-deployment)
  - [Docker Deployment](#docker-deployment)
  - [Testing](#testing)
  - [Demo videos](#demo-videos)
  - [How to contribute](#how-to-contribute)
  - [License](#license)
    - [Third-party component licenses](#third-party-component-licenses)
    - [License details](#license-details)

## Overview

TrustProvider Signer is a remote signing service provider and client.
This service is composed by three main servers:

- **App**: Spring Boot backend server that behaves as a CSC specification's RSSP.
- **Signature Application (SA)**: Spring Boot backend server that behaves similarly to the CSC specification's signature application.
- **Client**: React.js app that works as a server client for the backend servers.

### Features

The program implements the following features:

- **Create an Account**: Allows users to create new accounts within the program.
- **Authentication using OpenId4VP**: Enables authentication through OpenId4VP.
- **Create Certificates**: Enables authenticated users to create new certificates and their associated key pairs.
- **Sign Documents**: Allows an authenticated user to digitally sign documents with a chosen certificate.

## Disclaimer

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

This project uses a **MySQL** database, which is required for both **local** and **Docker-based** deployments. You can set up MySQL either on your **host machine** or inside a **Docker container**.

- [Local or Host Machine Setup](#local-or-host-machine-setup)
- [Docker Container Setup](#docker-container-setup)

#### Local or Host Machine Setup

1. **Install and Start MySQL**

   On Ubuntu or other Debian-based systems, you can install and start MySQL with the following commands:

   ```
   sudo apt install mysql-server -y
   sudo systemctl start mysql.service
   ```

2. **Create Database and User**

   Log in to MySQL as the root user:

   ```
   sudo mysql -u root -p
   ```

   Then, in the MySQL shell, create the database and user credentials for the Spring Boot application:

   ```
   CREATE DATABASE {database_name};
   CREATE USER {database_username}@{ip} IDENTIFIED BY {database_password};
   GRANT ALL PRIVILEGES ON {database_name}.* TO {database_username}@{ip};
   ```

   Replace placeholders as follows:

   - {ip} — IP address or hostname of the database (use 'localhost' if the database and services run on the same system)
   - {database_username} — trustprovider signer database username
   - {database_password} — trustprovider signer database password
   - {database_name} — name of the trustprovider signer database

   Example (for a local setup):

   ```
   CREATE USER {database_username}@'localhost' IDENTIFIED BY {database_password};
   GRANT ALL PRIVILEGES ON {database_name}.* TO {database_username}@'localhost';
   ```

3. **Create tables in the database**

   Create a table named **'event'** with the following SQL commands:

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

   **Alternative - Using a Setup Script**: The script **create_database.sql** is available in the **tools** directory. Update the placeholders '{database_name}', '{database_username}' and '{database_password}' in the script, then execute it to automatically create the database, user, and tables.

4. **Configure Environment Variables and Application Settings**

   Add the database variables {database_name}, {database_username}, and {database_password} to your configuration file.

   For example, in a .env file (see [.env File Setup](#env-file-setup)):

   ```
   SPRING_DATASOURCE_SERVER={database_host_url}
   SPRING_DATASOURCE_DATABASE={database_name}
   SPRING_DATASOURCE_USERNAME={database_username}
   SPRING_DATASOURCE_PASSWORD={database_password}
   ```

   Or, in **application.yml** (in the _resources_ folder in the module **app**):

   ```
   datasource:
      username: ${SPRING_DATASOURCE_USERNAME}
      password: ${SPRING_DATASOURCE_PASSWORD}
      url: jdbc:mysql://{SPRING_DATASOURCE_SERVER}/{SPRING_DATASOURCE_DATABASE}?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC&useLegacyDatetimeCode=false
      driver-class-name: com.mysql.cj.jdbc.Driver
   ```

   For Docker deployments, if the MySQL server runs on the host machine and the Spring Boot services are containerized, set:

   ```
   SPRING_DATASOURCE_SERVER=host.docker.internal:3306
   ```

   or directly in YAML:

   ```
   datasource:
      url: jdbc:mysql://host.docker.internal:3306/{database_name}?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC&useLegacyDatetimeCode=false
   ```

#### Docker Container Setup

You can also set up the MySQL database inside a Docker container. A service definition is already included in docker-compose.yml.

Make sure to update the following environment variables in the file: **MYSQL_DATABASE**, **MYSQL_USER**, **MYSQL_PASSWORD**, and **MYSQL_ROOT_PASSWORD**.

```
mysql:
  image: mysql/mysql-server:latest
  container_name: mysql
  restart: always
  environment:
    MYSQL_DATABASE: {database_trustprovider_name}
    MYSQL_USER: {database_trustprovider_username}
    MYSQL_PASSWORD: {database_trustprovider_password}
    MYSQL_ROOT_PASSWORD: {database_root_user}
  ports:
    - '3306:3306'
  volumes:
    - ./tools/db/create_database.sql:/docker-entrypoint-initdb.d/init.sql
    - mysql-volume:/var/lib/mysql
  networks:
    - backend
```

Finally, update the corresponding database connection variables in your **.env** file:

```
SPRING_DATASOURCE_DB_URL=localhost:3306 or mysql:3306
SPRING_DATASOURCE_DB_NAME={database_trustprovider_name}
SPRING_DATASOURCE_USERNAME={database_trustprovider_username}
SPRING_DATASOURCE_PASSWORD={database_trustprovider_password}
```

_Note:_ Use mysql:3306 if both MySQL and your Spring Boot app run as services in the same Docker network. Use localhost:3306 if the app runs on your host machine while the database runs in Docker.

### (Optional) HSM Configuration

The Trust Provider Signer supports the use of a _Hardware Security Module_ (HSM) for securely generating and storing cryptographic keys used in certificate creation.

Starting with **release 0.5.0**, HSM usage is optional. If no HSM is configured, the system automatically falls back to **Bouncy Castle** for key pair generation and signing operations.

1. **Enable HSM Support**

   You can enable HSM integration by setting the following configuration:

   - In **application.yml** (under the app module):

     ```
     keys:
         use-hsm: true
     ```

   - Or, in **.env** file:

     ```
     KEYS_USE_HSM=true
     ```

2. **Configure HSM Connection**

   This project uses the [jacknji11](https://github.com/joelhockey/jacknji11) library to communicate with PKCS#11-compatible HSMs. After deploying or connecting your HSM, define the following environment variables to provide the required PKCS#11 parameters:

   ```bash
   JACKNJI11_PKCS11_LIB_PATH={path_to_hsm_library} # Path to the HSM’s PKCS#11 shared library (e.g., /usr/local/lib/libcs_pkcs11_R2.so)
   JACKNJI11_TEST_TESTSLOT={slot} # Slot ID or token label of the HSM
   JACKNJI11_TEST_INITSLOT={slot} # Slot ID or token label of the HSM
   JACKNJI11_TEST_SO_PIN={security_officer_pin} # Security Officer (SO) PIN used for administrative initialization
   JACKNJI11_TEST_USER_PIN={user_pin} # User PIN used by the application to access private keys
   ```

   **Note:** For local deployment, set these variables directly in your shell or system environment rather than using .env because Spring Boot doesn't automatically map .env variables in this case.

3. **Compatibility**

   This version of the program was tested with the **Utimaco vHSM** using the **PKCS#11** protocol. Other PKCS#11-compliant HSMs may also be supported with proper configuration.

### (Optional) Configure EJBCA

The Trust Provider Signer can integrate with an external EJBCA instance for certificate issuance and management.
This integration is optional from **release 0.5.0** and if EJBCA is not configured, the application automatically falls back to creating a local Certificate Authority (CA) using an internally generated certificate and private key.

1. **Enable EJBCA Integration**

   To enable EJBCA integration, set the following configuration:

   - In **application.yml** (under the app module):

   ```
   certificates:
       use-ejbca: true
   ```

   - Or, in **.env** file:

   ```
   CERTIFICATES_USE_EJBCA=true
   ```

2. **Configure EJBCA Deployment (Optional, via Docker)**

   If you wish to run EJBCA in Docker, you can enable the predefined configuration included in the docker-compose.yml file.

   Simply **uncomment** the relevant lines for the EJBCA and EJBCA database services:

   ```
   trust_provider_signer_server_app:
     (...)
     depends_on:
       #ejbca:
       #  condition: service_healthy

   (...)

   #ejbca-database:
   #  image: mariadb:latest
   #  container_name: ejbca-database
   #  restart: always
   #  environment:
   #    MYSQL_ROOT_PASSWORD: {database_root_user}
   #    MYSQL_DATABASE: ejbca
   #    MYSQL_USER: {database_ejbca_username}
   #    MYSQL_PASSWORD: {database_ejbca_password}
   #  volumes:
   #    - ./datadbdir:/var/lib/mysql:rw
   #  networks:
   #    - application-bridge
   #ejbca:
   #  image: keyfactor/ejbca-ce:latest
   #  container_name: ejbca
   #  depends_on:
   #    - ejbca-database
   #  environment:
   #    DATABASE_JDBC_URL: jdbc:mariadb://ejbca-database:3306/ejbca?characterEncoding=UTF-8
   #    LOG_LEVEL_APP: INFO
   #    LOG_LEVEL_SERVER: INFO
   #    TLS_SETUP_ENABLED: simple
   #  ports:
   #    - "80:8080"
   #    - "443:8443"
   #  networks:
   #    - application-bridge
   #    - backend
   #  healthcheck:
   #    test: [ "CMD", "curl", "-f", "http://localhost:8080/ejbca/publicweb/healthcheck/ejbcahealth" ]
   #    interval: 15s
   #    timeout: 5s
   #    retries: 20
   ```

3. **Configure EJBCA Connection**

   After deploying EJBCA, define the following environment variables to allow the application to connect and issue certificates:

   ```
   EJBCA_HOST={ejbca_host_url}
   EJBCA_CLIENT_P12_FILEPATH={path_to_client_p12_file}
   EJBCA_CLIENT_P12_PASSWORD={p12_password}
   EJBCA_MANAGEMENT_CA={management_ca_name}
   EJBCA_CERTIFICATE_PROFILE_NAME={certificate_profile}
   EJBCA_END_ENTITY_PROFILE_NAME={end_entity_profile}
   EJBCA_USERNAME={ejbca_username}
   EJBCA_PASSWORD={ejbca_password}
   ```

   Alternatively, you can define these values directly in the **application.yml** file:

   ```
   certificates:
       use-ejbca: ${CERTIFICATES_USE_EJBCA}
       ejbca:
           # Values required to access the EJBCA:
           cahost: ${EJBCA_HOST}
           clientP12ArchiveFilepath: ${EJBCA_CLIENT_P12_FILEPATH}
           clientP12ArchivePassword: ${EJBCA_CLIENT_P12_PASSWORD}
           managementCA: ${EJBCA_MANAGEMENT_CA}
           # Endpoint:
           endpoint: /certificate/pkcs10enroll
           # Values required by the endpoint "/pkcs10enroll":
           certificateProfileName: ${EJBCA_CERTIFICATE_PROFILE_NAME}
           endEntityProfileName: ${EJBCA_END_ENTITY_PROFILE_NAME}
           username: ${EJBCA_USERNAME}
           password: ${EJBCA_PASSWORD}
           includeChain: true
           countries:
               - country: CZ
                 certificateAuthorityName: PID Issuer CA - CZ 02
               - country: EE
                 certificateAuthorityName: PID Issuer CA - EE 02
               - country: EU
                 certificateAuthorityName: PID Issuer CA - EU 02
               - country: LU
                 certificateAuthorityName: PID Issuer CA - LU 02
               - country: NL
                 certificateAuthorityName: PID Issuer CA - NL 02
               - country: PT
                 certificateAuthorityName: PID Issuer CA - PT 02
               - country: default
                 certificateAuthorityName: PID Issuer CA - UT 02
   ```

4. **Local CA (Fallback Configuration)**

   If you do not wish to use EJBCA, set the EJBCA integration flag (_CERTIFICATES_USE_EJBCA_) to _false_ and configure the local CA parameters instead:

   ```
   CERTIFICATES_USE_EJBCA=false
   CERTIFICATES_CA_SUBJECT_CERTIFICATE_FILE={path_to_ca_certificate}
   CERTIFICATES_CA_SUBJECT_KEY_FILE={path_to_ca_private_key}
   CERTIFICATES_CA_SUBJECT_COMMON_NAME={ca_common_name}
   CERTIFICATES_CA_SUBJECT_ORGANIZATION={ca_organization_name}
   CERTIFICATES_CA_SUBJECT_COUNTRY={ca_country_code}
   ```

   In this mode, the application generates or uses a local CA for signing operations, ensuring full functionality without an external certificate authority.

### .env File Setup

To deploy the TrustProvider Signer, you must create a .env file containing all required environment variables.
This file centralizes configuration details for database access, encryption, and the optional EJBCA and HSM components integrations.
Additional information about the expected values for each variable will be given in the next sections of this README.md.
Create a .env file in the root of your project and define the following variables:

```
# --- Database Config ---
# See section 'Database Setup' in README.md

SPRING_DATASOURCE_DB_URL={database_url} # Example: host.docker.internal:3306 or localhost:3306 or mysql:3306
SPRING_DATASOURCE_DB_NAME={database_name}
SPRING_DATASOURCE_USERNAME={database_username}
SPRING_DATASOURCE_PASSWORD={database_password}

# --- Secret Key Encryption ---
AUTH_DB_ENCRYPTION_PASSPHRASE= # Passphrase for encrypting secret keys stored in the database
AUTH_DB_ENCRYPTION_SALT=       # Base64-encoded salt used with the passphrase to derive the encryption key

# --- Tokens Secrets ---
AUTH_JWT_TOKEN_SECRET= # the BASE64-encoded signing key for the JWT token generation: used to digitally sign the JWT
AUTH_SAD_TOKEN_SECRET= # the BASE64-encoded signing key for SAD token generation: used to digitally sign the SAD token

# --- EJBCA Configuration ---
# See section 'Configure EJBCA' in README.md

CERTIFICATES_USE_EJBCA=               # (Optional) Boolean that indicates the use of EJBCA for certificate creation
CERTIFICATES_CA_SUBJECT_CERTIFICATE_FILE= # (Optional) Path where the created CA certificate will be stored and later loaded from
CERTIFICATES_CA_SUBJECT_KEY_FILE=     # (Optional) Path where the created CA private key will be stored and later loaded from
CERTIFICATES_CA_SUBJECT_COMMON_NAME=  # (Optional) Common Name of the certificate of the Certificate Authority
CERTIFICATES_CA_SUBJECT_ORGANIZATION= # (Optional) Organization of the certificate of the Certificate Authority
CERTIFICATES_CA_SUBJECT_COUNTRY=      # (Optional) Country of the certificate of the Certificate Authority

EJBCA_HOST=                     # (Optional) EJBCA service hostname or IP
EJBCA_CLIENT_P12_FILEPATH=      # (Optional) Path to the client .pfx/.p12 certificate file
EJBCA_CLIENT_P12_PASSWORD=      # (Optional) Password for the P12 file
EJBCA_MANAGEMENT_CA=            # (Optional) Path to the ManagementCA file
EJBCA_CERTIFICATE_PROFILE_NAME= # (Optional) Name of the certificate profile in EJBCA
EJBCA_END_ENTITY_PROFILE_NAME=  # (Optional) Name of the end entity profile in EJBCA
EJBCA_USERNAME=                 # (Optional) EJBCA API username
EJBCA_PASSWORD=                 # (Optional) EJBCA API password

# --- Keys Configuration ---
# See section '(Optional) HSM Configuration' in README.md

KEYS_USE_HSM= # Boolean that indicates the use of HSM for key pair creation

# --- HSM / PKCS#11 Configuration ---
# See section '(Optional) HSM Configuration' in README.md

JACKNJI11_PKCS11_LIB_PATH= # Path to your PKCS#11 .so library
JACKNJI11_TEST_INITSLOT=   # Initial HSM slot identifier
JACKNJI11_TEST_TESTSLOT=   # Secondary HSM slot identifier
JACKNJI11_TEST_USER_PIN=   # HSM user PIN
JACKNJI11_TEST_SO_PIN=     # HSM security officer PIN

# ---------- CLIENT ENVS -------------
ASSINA_RSSP_BASE_URL=
ASSINA_SA_BASE_URL=
ASSINA_CLIENT_BASE_URL=

# ---------- ReactJS Services URLs -------------
REACT_APP_APP_BASE_URL=
REACT_APP_SA_BASE_URL=
REACT_APP_CLIENT_BASE_URL=
```

## Local Deployment

### Requirements

- Node (nodejs & npm)
- Java: version 16
- Maven
- Follow [Prerequisites](#prerequisites)

### Configure Trusted CAs

To validate the vp_token received in the OID4VP authentication, it is necessary to validate the issuer of the certificate used in the signature in the MSO MDoc. The application validates that the issuer is one of the trusted CAs known.

The trusted CAs' certificate are stored in the folder _'issuersCertificates'_ in _'server'_.

If you wish to update the issuers accepted by the application, add the certificate to the folder _'issuersCertificate'_.

### Configure the App's application.yml

In order to configure the **App** server, you will need to update the **application.yml** file in the path "server/app/src/main/resources/".

You can either update the next parameters directly in the **application.yml** file or setting up the variables in the .env file while **uncommenting** the following lines in the **application.yml**:

```
spring:
    config:
      import: file:${PROJECT_ROOT:.}/../.env[.properties]
```

1. **Update the Datasource Configuration**

   Update the following lines in the **application.yml** or set up the variables in the **.env** file in the root directory, with the variables from the [Database Setup](#database-setup) :

   ```
      datasource:
       username: ${SPRING_DATASOURCE_USERNAME}
       password: ${SPRING_DATASOURCE_PASSWORD}
       url: jdbc:mysql://${SPRING_DATASOURCE_SERVER}/${SPRING_DATASOURCE_DATABASE}?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC&useLegacyDatetimeCode=false
       driver-class-name: com.mysql.cj.jdbc.Driver
   ```

2. **Update the JWTs and SADs secrets**

   Replace the variables _AUTH_JWT_TOKEN_SECRET_ and _AUTH_SAD_TOKEN_SECRET_ in the **application.yml** or set up the variables in the **.env** file in the root directory. This variables will corresponde to a BASE64-encoded signing key for the JWT token generation, which will be used to digitally sign the JWT and a BASE64-encoded signing key for SAD token generation for digitally sign the SAD token, respectively.

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

3. **(Optional) Configure EJBCA Integration**

   The Trust Provider Signer can optionally integrate with an EJBCA server for certificate issuance and management.
   By default, if EJBCA is not configured, the system automatically falls back to a local CA using internally generated certificates.

   To enable or customize EJBCA integration, follow the instructions in the section [(Optional) EJBCA Configuration](#optional-configure-ejbca).

4. **Authentication using OpenId4VP**

   This application requires users to authenticate and authorize the signature of documents with certificates they own through their EUDI Wallet.
   To enable this feature, communication with a backend **Verifier** is necessary. Define the address, URL and the client*id of the Verifier by adding the configuration in **application.yml** located in the folder \_server/app/src/main/resources*:

   ```
   verifier:
      url:
      address:
      client_id:
   ```

   By default, this configuration is set to a backend server based on the code from the github **'eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt'**. Therefore, the default configuration is:

   ```
   verifier:
      url: https://verifier-backend.eudiw.dev/ui/presentations
      address: verifier-backend.eudiw.dev
      client_id: verifier-backend.eudiw.dev
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

### Configure Signature Application's (SA) application.yml

In order to configure the **SA** server, you will need to update the **application.yml** file in the path "server/sa/src/main/resources/".

You can either update the next parameters directly in the **application.yml** file or setting up the variables in the **.env** file while uncommenting the following lines in the **application.yml**:

```
spring:
    config:
      import: file:${PROJECT_ROOT:.}/../.env[.properties]
```

1. **Update App's CSC Url**

   The Signature Application (SA) needs to know the url of the CSC endpoints. The URL can be defined in the following lines from the **application.yml**, or by setting up the variables in the **.env** file in the root directory:

   ```
   rssp:
    cscBaseUrl: ${CSC_BASE_URL}
   ```

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

We may need to define volumes for the HSM and EJBCA configuration, it there are used, in the _docker-compose.yml_.

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
