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

CREATE DATABASE {database_name};
CREATE USER {database_username}@ip identified by {database_password};
GRANT ALL PRIVILEGES ON {database_name}.* TO {database_username}@ip;

USE {database_name};

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