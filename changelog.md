# Changelog

## [0.3.0]

_12 Jun 2024_

### Added:

-   Management of the local variables required by the login process and the OID4VP.
-   Additional unit tests.
-   A local trusted issuers list, with the trusted CAs certificates.
-   Validation of the VP Token received.
-   Demo videos.
-   Surname and given name to the certificates created.
-   Visible representation of the PDF's signature.
-   Hardware Security Modules support.

### Changed

-   Updated the debug logs.
-   Frontend updates: additional user logs, improved error pop-up messages, added logo to the QR codes, updated footer, and additional validation to the user input and request actions.
-   Updated the body of the messages sent to the OID4VP Verifier.
-   Improved the EJBCA configuration file to easily add support for new and multiple CAs.
-   Updated the namespace/package name of the Java classes.
-   Changed the signature process to use the DSS library.
-   Refactored code and removed unused code.
-   Added additional verification to the requested actions and additional error handling.

### Fixed

-   Issue #23: "Error when trying to sign a file without having a certificate."
-   Issue #27: "Failed to load resource: the server responded with a status of 504 (Gateway Time-out)."
-   Issue #28: "WebSocket connection to 'wss://trustprovider.signer.eudiw.dev:3000/ws.' failed: An SSL error has occurred and a secure connection to the server cannot be made."
-   Issue #29: "If the user enters the same alias twice, then an error appears."
-   Issue #30: "Log in as user X and sign in as user Y."
-   Issue #58: "Bug: Verification of the VP Token received from the authentication with Sample Documents has failed."

## [0.2.0]

_28 Fev 2024_

### Added

-   Added an alias associated with the certificate.
-   Enabled login and sign-in using OID4VP to allow the usage of EUDIW and enable signing authorization using OID4VP. This includes the management of local variables and displaying a deep link/QR code to redirect to a wallet.
-   Added a record of the actions executed by the user, named "logs".
-   Improved the frontend layout.
-   Added trust hierarchy to the signature of the PDF.
-   Added a feature to delete certificates.

### Changed

-   Changed the issuance of certificates from self-signed to certificates signed by a CA (using EJBCA).
-   Enabled selecting the certificate to use for signing a PDF by alias.
-   Updated user data (added hash).
-   Updated project configuration to facilitate deployment on a remote machine.
-   Corrected the download process.
