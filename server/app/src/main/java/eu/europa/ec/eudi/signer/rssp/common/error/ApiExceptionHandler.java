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

package eu.europa.ec.eudi.signer.rssp.common.error;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import eu.europa.ec.eudi.signer.common.ApiError;
import eu.europa.ec.eudi.signer.common.ApiErrorResponse;
import eu.europa.ec.eudi.signer.csc.error.CSCInvalidRequest;

/**
 * Captures exceptions going out of the REST layer and converts ApiErrors into
 * proper
 * error responses. The error response deliberately matches that prescribed in
 * the
 * CSC spec v1.0.4.0
 *
 * Example: (From 10.1 of CSC spec 1.0.4.0)
 * HTTP/1.1 400 Bad Request
 * Date: Mon, 03 Dec 2018 12:00:00 GMT Content-Type:
 * application/json;charset=utf-8
 * Content-Length: ...
 * {
 * "error": "invalid_request",
 * "error_description": "The access token is not valid"
 * }
 */
@ControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {
	private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

	@ExceptionHandler(value = { ApiException.class })
	protected ResponseEntity<?> handleApiException(RuntimeException exception, WebRequest request) {
		ApiError apiError = ((ApiException) exception).getApiError();
		String message = exception.getMessage();
		return apiErrorToResponse(apiError, message, exception, request);
	}

	private ResponseEntity<Object> apiErrorToResponse(ApiError error, String message, Exception ex, WebRequest request) {
		ApiErrorResponse response = new ApiErrorResponse(error.getCode(), error.getDescription());
		HttpStatus httpStatus = HttpStatus.valueOf(error.getHttpCode());
		// log a warning for all messages
		log.warn("Responding to error: {} with status {}. Error description {}; message: {}", error.getCode(), error.getHttpCode(), error.getDescription(), message);
		return handleExceptionInternal(ex, response, new HttpHeaders(), httpStatus, request);
	}

	@Override
	@Nullable
	protected ResponseEntity<Object> handleExceptionInternal(@NotNull Exception exception, @Nullable Object body, @NotNull HttpHeaders headers, @NotNull HttpStatusCode status, @NotNull WebRequest request) {
		if (exception instanceof ApiException) {
			log.debug("Handled exception in TrustProviderSigner application", exception);
			log.warn("Handled Error: " + exception.getMessage(), (Object[]) ((ApiException) exception).getMessageParams());
		} else {
			log.error("Unhandled exception in TrustProviderSigner application", exception);
		}
		return super.handleExceptionInternal(exception, body, headers, status, request);
	}

	/**
	 * Handle validation errors that are triggered by @Valid in the controllors and
	 * named by validation
	 * constraints on the payload methods like @NotNull or @NotBlank.
	 *
	 * The custom messages in these annotations match enum names for CSC or API
	 * errors so that the
	 * validation error can be converted to the proper error response body
	 * (according to the CSC spec)
	 */
	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, @NotNull HttpHeaders headers, @NotNull HttpStatusCode status, @NotNull WebRequest request) {
		ApiError apiError;
		if (ex.hasFieldErrors()) {
			FieldError fieldError = ex.getFieldError();
			if(fieldError == null){
				apiError = SignerError.UnexpectedValidationError;
			}
			else{
				String error = fieldError.getDefaultMessage();
				try {
					apiError = CSCInvalidRequest.valueOf(error);
				} catch (IllegalArgumentException e) {
					try {
						apiError = SignerError.valueOf(error);
					} catch (IllegalArgumentException e2) {
						apiError = SignerError.UnexpectedValidationError;
					}
				}
			}
		} else {
			apiError = SignerError.UnexpectedValidationError;
		}
		return apiErrorToResponse(apiError, ex.getMessage(), ex, request);
	}




}
