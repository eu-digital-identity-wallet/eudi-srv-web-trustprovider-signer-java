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

package eu.europa.ec.eudi.signer.sa.error;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.lang.Nullable;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import eu.europa.ec.eudi.signer.common.ApiError;
import eu.europa.ec.eudi.signer.common.ApiErrorResponse;

/**
 * Logs errors that occur in the Signing App
 */
@ControllerAdvice
public class ClientExceptionHandler extends ResponseEntityExceptionHandler {
	private static final Logger log = LoggerFactory.getLogger(ClientExceptionHandler.class);

	@ExceptionHandler(value = { RSSPClientException.class })
	protected ResponseEntity<?> handleClientException(RuntimeException ae, WebRequest request) {
		ApiError apiError = ((RSSPClientException) ae);
		String message = ae.getMessage();
		return apiErrorToResponse(apiError, message, ae, request);
	}

	@Override
	@Nullable
	protected ResponseEntity<Object> handleExceptionInternal(
		  Exception ex, @Nullable Object body, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
		log.error("Unhandled exception in Signing Application", ex);
		return super.handleExceptionInternal(ex, body, headers, status, request);
	}

	private ResponseEntity<Object> apiErrorToResponse(
			ApiError error, String message, Exception ex, WebRequest request) {
		ApiErrorResponse response = new ApiErrorResponse(error.getCode(), error.getDescription());
		HttpStatus httpStatus = HttpStatus.valueOf(error.getHttpCode());
		// log a warning for all messages
		log.warn("Responding to error: {} with status {}. Error description {}; message: {}",
				error.getCode(), error.getHttpCode(), error.getDescription(), message);

		return handleExceptionInternal(ex, response, new HttpHeaders(), httpStatus, request);
	}
}
