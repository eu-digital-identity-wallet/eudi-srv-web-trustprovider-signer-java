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

package eu.europa.ec.eudi.signer.sa.client;

import eu.europa.ec.eudi.signer.common.AccessCredentialDeniedException;
import eu.europa.ec.eudi.signer.common.FailedConnectionVerifier;
import eu.europa.ec.eudi.signer.common.TimeoutException;
import eu.europa.ec.eudi.signer.csc.payload.RedirectLinkResponse;

public interface SignerClient {

     /**
      * Function that allows to get the link to redirect a user to a EUDI Wallet
      * 
      * @return the deep link
      */
	RedirectLinkResponse getOIDRedirectLink(String redirect_uri);

	/**
      * Function that prepares the signer
      * 
      * @return the client context updated
      */
     ClientContext prepCredential();

     /**
      * Function that allows to sign a pdf.
      * 
      * @param pdfName the pdf name
      * @param pdfHash the pdf bytes
      * @param context the context
      * @return the array byte with the signature value
      * @throws FailedConnectionVerifier
      * @throws TimeoutException
      * @throws AccessCredentialDeniedException
      * @throws Exception
      */
     public byte[] signHash(String pdfName, byte[] pdfHash, String responseCode, ClientContext context)
               throws FailedConnectionVerifier, TimeoutException, AccessCredentialDeniedException, Exception;

}
