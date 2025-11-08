package eu.europa.ec.eudi.signer.rssp.security.openid4vp;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import eu.europa.ec.eudi.signer.rssp.common.config.TrustedIssuersCertificatesProperties;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;

import eu.europa.ec.eudi.signer.rssp.common.error.VerifiablePresentationVerificationException;
import id.walt.mdoc.doc.MDoc;

@SpringBootTest
@RunWith(SpringJUnit4ClassRunner.class)
public class VPValidatorTest {

    @Autowired
    private TrustedIssuersCertificatesProperties trustedIssuersCertificatesProperties;

    private JSONObject setVPTokenInString(String vp_token_cbor_hex, String presentation_definition_id,
            String presentation_definition_input_descriptors_id) throws JSONException {
		String message = "{\"vp_token\":\"" +
			  vp_token_cbor_hex +
			  "\",\"presentation_submission\":{\"id\":\"pid-res\",\"definition_id\":\"" +
			  presentation_definition_id +
			  "\",\"descriptor_map\":[{\"id\":\"" + presentation_definition_input_descriptors_id +
			  "\",\"format\":\"mso_mdoc\",\"path\":\"$\"}]}}";

        return new JSONObject(message);
    }

    @Test
    public void test_loadAndVerifyDocumentForVP_Success() {
        // Arrange
        VPValidator vp_validator = null;
        try {
            String vp_from_verifier = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBleBhldS5ldXJvcGEuZWMuZXVkaXcucGlkLjFsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xhtgYWGmkZnJhbmRvbVgggCpS0xCfgPmPD2zFhQNieYOwZsUPiQoHzpUCI7gWH7BoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZWlSb2RyaWd1ZXNxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhmpGZyYW5kb21YIIvNXv-shbvhLmg6RLHGDOUpKNcV9r7MocrpbX88RjQqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVnTWFyaWFuYXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYbKRmcmFuZG9tWCBOb54F3cjnU8BMqtl1Ha9mjYGSsE1G_9aBiwpCr41MKmhkaWdlc3RJRAFsZWxlbWVudFZhbHVl2QPsajIwMDEtMDMtMTlxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWGCkZnJhbmRvbVggCVL_ymTwJKhV0WktqqsFnK3ysLDCHM4ADSIfiDwsLt9oZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFh1pGZyYW5kb21YIFdIw3WsKTt_uFlXa8sRmO_EiNCwW-uU35bM2Pwx2x7IaGRpZ2VzdElEB2xlbGVtZW50VmFsdWVvVGVzdCBQSUQgaXNzdWVycWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYZqRmcmFuZG9tWCD1ZWNZV_hDbwzWvokzSsB3LQYW7GPaEQLSxD_qXCKNpWhkaWdlc3RJRAJsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWppc3N1ZXJBdXRohEOhASahGCFZAugwggLkMIICaqADAgECAhRyMm32Ywiae1APjD8mpoXLwsLSyjAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjMwOTAyMTc0MjUxWhcNMjQxMTI1MTc0MjUwWjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQR81BwtG6ZqjrWQYWWw5pPeGxzlr3ptXIr3ftI93rJ_KvC9TAgqJTakJAj2nV4yQGLJl0tw-PhwfbHDrIYsWKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBSB7_ScXIMKUKZGvvdQeFpTPj_YmzAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNoADBlAjBF-tqi7y2VU-u0iETYZBrQKp46jkord9ri9B55Xy8tkJsD8oEJlGtOLZKDrX_BoYUCMQCbnk7tUBCfXw63ACzPmLP-5BFAfmXuMPsBBL7Wc4Lqg94fXMSI5hAXZAEyJ0NATQpZAl3YGFkCWKZnZG9jVHlwZXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTAzLTE0VDEyOjQ1OjU4Wml2YWxpZEZyb23AdDIwMjQtMDMtMTRUMTI6NDU6NThaanZhbGlkVW50aWzAdDIwMjQtMDYtMTJUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6F4GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMagAWCAYu8laQ2gSMxNaN9U5QHjVYRM4YmsH5IjmZ78A_ko5rgFYIITEUHYCkJin4kegSfhfywqmIulzV64aaN4bBB_fFmtwAlggX3ZenlNuZ82FwTJ6B3pXHNRN2rPPp-_MzM9UcRAbNFMDWCBjfPdUXpQQrzl547MjZ80ZSPaCkKoJmoWTNhlEwoodjQRYIG1U-AMrIHwCA1UI9rcSSOvQtVahbGSaiV1DivEGwpUoBVggi-SxcXysAZwlghLqnrImAOqzKBTEqrWfGStpyeytf80GWCA8HQSd-zlLhWSPrEaZKcubpVCZ9CzbwTphuSEj1fKUAgdYIA_8siSHso4_-z4RE4rH4mHLyQvaQgRxUeEQ8409FVMIbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggU8-tu3KhBhsN4j8hEnytHCvFSRY7fZa1ZBZ85FDhWOsiWCAjoQopDY8VYUFL9V5OOs_BCuanfHstARFcBSCYSjLuIm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAB0EIHqYq27qIkuDxAUKGsgq91adUAp2n3CiqRnJmmV_nJHO5cs6bS4vEkLfuAeZeoYBNq01ZXPsr0TRfizx8B2xkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQFcqp8k7g4ai3Gis3RdmuJJH6sFxCEf7OkTYUC07wMSShIqyG26OpRtgL_a8-8oXbteNIxp3TMKS_Sl5npIWdCtmc3RhdHVzAA";
            String presentation_definition_id = "32f54163-7166-48f1-93d8-ff217bdb0653";
            String presentation_definition_input_descriptors_id = "eudi_pid";
            JSONObject vp_json_object = setVPTokenInString(vp_from_verifier, presentation_definition_id, presentation_definition_input_descriptors_id);
            vp_validator = new VPValidator(vp_json_object, this.trustedIssuersCertificatesProperties);
        } catch (Exception e) {
            Assert.assertNull(e);
        }

        Assert.assertNotNull(vp_validator);

        // Act
        MDoc document = null;
        try {
            Map<Integer, String> logs = new HashMap<>();
            document = vp_validator.loadAndVerifyDocumentForVP(logs);
        } catch (Exception e) {
            Assert.assertNull(e);
        }

        // Assert
        Assert.assertNotNull(document);
    }

    @Test
    public void test_loadAndVerifyDocumentsForVP_PresentationSubmissionDefinitionId_Fail() {

        VPValidator vp_validator = null;
        try {
            String vp_from_verifier = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBleBhldS5ldXJvcGEuZWMuZXVkaXcucGlkLjFsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xhtgYWGmkZnJhbmRvbVgggCpS0xCfgPmPD2zFhQNieYOwZsUPiQoHzpUCI7gWH7BoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZWlSb2RyaWd1ZXNxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhmpGZyYW5kb21YIIvNXv-shbvhLmg6RLHGDOUpKNcV9r7MocrpbX88RjQqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVnTWFyaWFuYXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYbKRmcmFuZG9tWCBOb54F3cjnU8BMqtl1Ha9mjYGSsE1G_9aBiwpCr41MKmhkaWdlc3RJRAFsZWxlbWVudFZhbHVl2QPsajIwMDEtMDMtMTlxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWGCkZnJhbmRvbVggCVL_ymTwJKhV0WktqqsFnK3ysLDCHM4ADSIfiDwsLt9oZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFh1pGZyYW5kb21YIFdIw3WsKTt_uFlXa8sRmO_EiNCwW-uU35bM2Pwx2x7IaGRpZ2VzdElEB2xlbGVtZW50VmFsdWVvVGVzdCBQSUQgaXNzdWVycWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYZqRmcmFuZG9tWCD1ZWNZV_hDbwzWvokzSsB3LQYW7GPaEQLSxD_qXCKNpWhkaWdlc3RJRAJsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWppc3N1ZXJBdXRohEOhASahGCFZAugwggLkMIICaqADAgECAhRyMm32Ywiae1APjD8mpoXLwsLSyjAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjMwOTAyMTc0MjUxWhcNMjQxMTI1MTc0MjUwWjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQR81BwtG6ZqjrWQYWWw5pPeGxzlr3ptXIr3ftI93rJ_KvC9TAgqJTakJAj2nV4yQGLJl0tw-PhwfbHDrIYsWKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBSB7_ScXIMKUKZGvvdQeFpTPj_YmzAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNoADBlAjBF-tqi7y2VU-u0iETYZBrQKp46jkord9ri9B55Xy8tkJsD8oEJlGtOLZKDrX_BoYUCMQCbnk7tUBCfXw63ACzPmLP-5BFAfmXuMPsBBL7Wc4Lqg94fXMSI5hAXZAEyJ0NATQpZAl3YGFkCWKZnZG9jVHlwZXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTAzLTE0VDEyOjQ1OjU4Wml2YWxpZEZyb23AdDIwMjQtMDMtMTRUMTI6NDU6NThaanZhbGlkVW50aWzAdDIwMjQtMDYtMTJUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6F4GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMagAWCAYu8laQ2gSMxNaN9U5QHjVYRM4YmsH5IjmZ78A_ko5rgFYIITEUHYCkJin4kegSfhfywqmIulzV64aaN4bBB_fFmtwAlggX3ZenlNuZ82FwTJ6B3pXHNRN2rPPp-_MzM9UcRAbNFMDWCBjfPdUXpQQrzl547MjZ80ZSPaCkKoJmoWTNhlEwoodjQRYIG1U-AMrIHwCA1UI9rcSSOvQtVahbGSaiV1DivEGwpUoBVggi-SxcXysAZwlghLqnrImAOqzKBTEqrWfGStpyeytf80GWCA8HQSd-zlLhWSPrEaZKcubpVCZ9CzbwTphuSEj1fKUAgdYIA_8siSHso4_-z4RE4rH4mHLyQvaQgRxUeEQ8409FVMIbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggU8-tu3KhBhsN4j8hEnytHCvFSRY7fZa1ZBZ85FDhWOsiWCAjoQopDY8VYUFL9V5OOs_BCuanfHstARFcBSCYSjLuIm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAB0EIHqYq27qIkuDxAUKGsgq91adUAp2n3CiqRnJmmV_nJHO5cs6bS4vEkLfuAeZeoYBNq01ZXPsr0TRfizx8B2xkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQFcqp8k7g4ai3Gis3RdmuJJH6sFxCEf7OkTYUC07wMSShIqyG26OpRtgL_a8-8oXbteNIxp3TMKS_Sl5npIWdCtmc3RhdHVzAA";
            String actual_presentation_definition_id = "32f54163-7166-48f1-93d8-ff217bdb0654";
            String actual_presentation_definition_input_descriptors_id = "eudi_pid";

            JSONObject vp_json_object = setVPTokenInString(vp_from_verifier, actual_presentation_definition_id,
                    actual_presentation_definition_input_descriptors_id);
            vp_validator = new VPValidator(vp_json_object, this.trustedIssuersCertificatesProperties);
        } catch (Exception e) {
            Assert.assertNull(e);
        }

        Assert.assertNotNull(vp_validator);

        // Act & Assert
        try {
            Map<Integer, String> logs = new HashMap<>();
            vp_validator.loadAndVerifyDocumentForVP(logs);
        } catch (Exception e) {
            Assert.assertNotNull(e);
            Assert.assertEquals(e.getMessage(),
                    "Verification of the Verifiable Presentation Failed: definition_id in presentation_submission is not the expected.");
        }
    }

    @Test
    public void test_loadAndVerifyDocumentsForVP_PresentationSubmissionInputDescriptorsId_Fail() {
        VPValidator vp_validator = null;
        try {
            String vp_from_verifier = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBleBhldS5ldXJvcGEuZWMuZXVkaXcucGlkLjFsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xhtgYWGmkZnJhbmRvbVgggCpS0xCfgPmPD2zFhQNieYOwZsUPiQoHzpUCI7gWH7BoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZWlSb2RyaWd1ZXNxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhmpGZyYW5kb21YIIvNXv-shbvhLmg6RLHGDOUpKNcV9r7MocrpbX88RjQqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVnTWFyaWFuYXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYbKRmcmFuZG9tWCBOb54F3cjnU8BMqtl1Ha9mjYGSsE1G_9aBiwpCr41MKmhkaWdlc3RJRAFsZWxlbWVudFZhbHVl2QPsajIwMDEtMDMtMTlxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWGCkZnJhbmRvbVggCVL_ymTwJKhV0WktqqsFnK3ysLDCHM4ADSIfiDwsLt9oZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFh1pGZyYW5kb21YIFdIw3WsKTt_uFlXa8sRmO_EiNCwW-uU35bM2Pwx2x7IaGRpZ2VzdElEB2xlbGVtZW50VmFsdWVvVGVzdCBQSUQgaXNzdWVycWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYZqRmcmFuZG9tWCD1ZWNZV_hDbwzWvokzSsB3LQYW7GPaEQLSxD_qXCKNpWhkaWdlc3RJRAJsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWppc3N1ZXJBdXRohEOhASahGCFZAugwggLkMIICaqADAgECAhRyMm32Ywiae1APjD8mpoXLwsLSyjAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjMwOTAyMTc0MjUxWhcNMjQxMTI1MTc0MjUwWjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQR81BwtG6ZqjrWQYWWw5pPeGxzlr3ptXIr3ftI93rJ_KvC9TAgqJTakJAj2nV4yQGLJl0tw-PhwfbHDrIYsWKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBSB7_ScXIMKUKZGvvdQeFpTPj_YmzAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNoADBlAjBF-tqi7y2VU-u0iETYZBrQKp46jkord9ri9B55Xy8tkJsD8oEJlGtOLZKDrX_BoYUCMQCbnk7tUBCfXw63ACzPmLP-5BFAfmXuMPsBBL7Wc4Lqg94fXMSI5hAXZAEyJ0NATQpZAl3YGFkCWKZnZG9jVHlwZXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTAzLTE0VDEyOjQ1OjU4Wml2YWxpZEZyb23AdDIwMjQtMDMtMTRUMTI6NDU6NThaanZhbGlkVW50aWzAdDIwMjQtMDYtMTJUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6F4GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMagAWCAYu8laQ2gSMxNaN9U5QHjVYRM4YmsH5IjmZ78A_ko5rgFYIITEUHYCkJin4kegSfhfywqmIulzV64aaN4bBB_fFmtwAlggX3ZenlNuZ82FwTJ6B3pXHNRN2rPPp-_MzM9UcRAbNFMDWCBjfPdUXpQQrzl547MjZ80ZSPaCkKoJmoWTNhlEwoodjQRYIG1U-AMrIHwCA1UI9rcSSOvQtVahbGSaiV1DivEGwpUoBVggi-SxcXysAZwlghLqnrImAOqzKBTEqrWfGStpyeytf80GWCA8HQSd-zlLhWSPrEaZKcubpVCZ9CzbwTphuSEj1fKUAgdYIA_8siSHso4_-z4RE4rH4mHLyQvaQgRxUeEQ8409FVMIbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggU8-tu3KhBhsN4j8hEnytHCvFSRY7fZa1ZBZ85FDhWOsiWCAjoQopDY8VYUFL9V5OOs_BCuanfHstARFcBSCYSjLuIm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAB0EIHqYq27qIkuDxAUKGsgq91adUAp2n3CiqRnJmmV_nJHO5cs6bS4vEkLfuAeZeoYBNq01ZXPsr0TRfizx8B2xkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQFcqp8k7g4ai3Gis3RdmuJJH6sFxCEf7OkTYUC07wMSShIqyG26OpRtgL_a8-8oXbteNIxp3TMKS_Sl5npIWdCtmc3RhdHVzAA";
            String actual_presentation_definition_id = "32f54163-7166-48f1-93d8-ff217bdb0654";
            String actual_presentation_definition_input_descriptors_id = "eudi_pids";

            JSONObject vp_json_object = setVPTokenInString(vp_from_verifier, actual_presentation_definition_id,
                    actual_presentation_definition_input_descriptors_id);
            vp_validator = new VPValidator(vp_json_object, this.trustedIssuersCertificatesProperties);
        } catch (Exception e) {
            Assert.assertNull(e);
        }

        Assert.assertNotNull(vp_validator);

        // Act & Assert
        try {
            Map<Integer, String> logs = new HashMap<>();
            vp_validator.loadAndVerifyDocumentForVP(logs);
        } catch (Exception e) {
            Assert.assertNotNull(e);
            Assert.assertEquals(
                    "Verification of the Verifiable Presentation Failed: No descriptor_map in the presentation_submission contains information about the requested VP.",
                    e.getMessage());
        }
    }

    private String changeStatus(String vp_token) throws JSONException {
        byte[] bytesCBOR = Base64.getUrlDecoder().decode(vp_token);
        CBORObject cborObject = CBORObject.DecodeFromBytes(bytesCBOR);
        cborObject.set("status", CBORObject.FromInt32(10));
        byte[] bytes = cborObject.EncodeToBytes();
		return Base64.getUrlEncoder().encodeToString(bytes);
    }

    @Test
    public void test_loadAndVerifyDocumentsForVP_StatusInvalidFail() {
        VPValidator vp_validator = null;
        try {
            String vp_from_verifier = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBleBhldS5ldXJvcGEuZWMuZXVkaXcucGlkLjFsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xhtgYWGmkZnJhbmRvbVgggCpS0xCfgPmPD2zFhQNieYOwZsUPiQoHzpUCI7gWH7BoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZWlSb2RyaWd1ZXNxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhmpGZyYW5kb21YIIvNXv-shbvhLmg6RLHGDOUpKNcV9r7MocrpbX88RjQqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVnTWFyaWFuYXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYbKRmcmFuZG9tWCBOb54F3cjnU8BMqtl1Ha9mjYGSsE1G_9aBiwpCr41MKmhkaWdlc3RJRAFsZWxlbWVudFZhbHVl2QPsajIwMDEtMDMtMTlxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWGCkZnJhbmRvbVggCVL_ymTwJKhV0WktqqsFnK3ysLDCHM4ADSIfiDwsLt9oZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFh1pGZyYW5kb21YIFdIw3WsKTt_uFlXa8sRmO_EiNCwW-uU35bM2Pwx2x7IaGRpZ2VzdElEB2xlbGVtZW50VmFsdWVvVGVzdCBQSUQgaXNzdWVycWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYZqRmcmFuZG9tWCD1ZWNZV_hDbwzWvokzSsB3LQYW7GPaEQLSxD_qXCKNpWhkaWdlc3RJRAJsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWppc3N1ZXJBdXRohEOhASahGCFZAugwggLkMIICaqADAgECAhRyMm32Ywiae1APjD8mpoXLwsLSyjAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjMwOTAyMTc0MjUxWhcNMjQxMTI1MTc0MjUwWjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQR81BwtG6ZqjrWQYWWw5pPeGxzlr3ptXIr3ftI93rJ_KvC9TAgqJTakJAj2nV4yQGLJl0tw-PhwfbHDrIYsWKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBSB7_ScXIMKUKZGvvdQeFpTPj_YmzAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNoADBlAjBF-tqi7y2VU-u0iETYZBrQKp46jkord9ri9B55Xy8tkJsD8oEJlGtOLZKDrX_BoYUCMQCbnk7tUBCfXw63ACzPmLP-5BFAfmXuMPsBBL7Wc4Lqg94fXMSI5hAXZAEyJ0NATQpZAl3YGFkCWKZnZG9jVHlwZXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTAzLTE0VDEyOjQ1OjU4Wml2YWxpZEZyb23AdDIwMjQtMDMtMTRUMTI6NDU6NThaanZhbGlkVW50aWzAdDIwMjQtMDYtMTJUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6F4GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMagAWCAYu8laQ2gSMxNaN9U5QHjVYRM4YmsH5IjmZ78A_ko5rgFYIITEUHYCkJin4kegSfhfywqmIulzV64aaN4bBB_fFmtwAlggX3ZenlNuZ82FwTJ6B3pXHNRN2rPPp-_MzM9UcRAbNFMDWCBjfPdUXpQQrzl547MjZ80ZSPaCkKoJmoWTNhlEwoodjQRYIG1U-AMrIHwCA1UI9rcSSOvQtVahbGSaiV1DivEGwpUoBVggi-SxcXysAZwlghLqnrImAOqzKBTEqrWfGStpyeytf80GWCA8HQSd-zlLhWSPrEaZKcubpVCZ9CzbwTphuSEj1fKUAgdYIA_8siSHso4_-z4RE4rH4mHLyQvaQgRxUeEQ8409FVMIbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggU8-tu3KhBhsN4j8hEnytHCvFSRY7fZa1ZBZ85FDhWOsiWCAjoQopDY8VYUFL9V5OOs_BCuanfHstARFcBSCYSjLuIm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAB0EIHqYq27qIkuDxAUKGsgq91adUAp2n3CiqRnJmmV_nJHO5cs6bS4vEkLfuAeZeoYBNq01ZXPsr0TRfizx8B2xkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQFcqp8k7g4ai3Gis3RdmuJJH6sFxCEf7OkTYUC07wMSShIqyG26OpRtgL_a8-8oXbteNIxp3TMKS_Sl5npIWdCtmc3RhdHVzAA";
            String vp_token = changeStatus(vp_from_verifier);

            String presentation_definition_id = "32f54163-7166-48f1-93d8-ff217bdb0653";
            String presentation_definition_input_descriptors_id = "eudi_pid";

            JSONObject vp_json_object = setVPTokenInString(vp_token, presentation_definition_id,
                    presentation_definition_input_descriptors_id);
            vp_validator = new VPValidator(vp_json_object, this.trustedIssuersCertificatesProperties);
        } catch (Exception e) {
            Assert.assertNull(e);
        }

        Assert.assertNotNull(vp_validator);

        // Act & Assert
        try {
            Map<Integer, String> logs = new HashMap<>();
            vp_validator.loadAndVerifyDocumentForVP(logs);
        } catch (Exception e) {
            Assert.assertNotNull(e);
            Assert.assertEquals(
                    "Verification of the Verifiable Presentation Failed: The vp_token's status is not equal to a successful status.",
                    e.getMessage());
        }
    }

    // Verify Certificate Fail

    // Verify Signature Fail
    private String changeSignatureValue(String vp_token) throws Exception {
        byte[] bytesCBOR = Base64.getUrlDecoder().decode(vp_token);
        CBORObject cborObject = CBORObject.DecodeFromBytes(bytesCBOR);
        CBORObject documents = cborObject.get("documents");
        CBORObject document = documents.get(0);
        CBORObject issuerSigned = document.get("issuerSigned");
        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        byte[] currentSignature = issuerAuth.get(3).GetByteString();
        byte[] newSignature = Arrays.copyOf(currentSignature, currentSignature.length - 1);
        issuerAuth.set(3, CBORObject.FromByteArray(newSignature));
        issuerSigned.set("issuerAuth", issuerAuth);
        document.set("issuerSigned", issuerSigned);
        documents.set(0, document);
        cborObject.set("documents", documents);
        byte[] bytes = cborObject.EncodeToBytes();
		return Base64.getUrlEncoder().encodeToString(bytes);
    }

    private String changePayloadValue(String vp_token) throws JSONException {
        byte[] bytesCBOR = Base64.getUrlDecoder().decode(vp_token);
        CBORObject cborObject = CBORObject.DecodeFromBytes(bytesCBOR);
        CBORObject documents = cborObject.get("documents");
        CBORObject document = documents.get(0);
        CBORObject issuerSigned = document.get("issuerSigned");
        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        CBORObject payload = issuerAuth.get(2);
        byte[] currentPayload = payload.GetByteString();
        currentPayload[currentPayload.length - 1] = (byte) 0;
        CBORObject payloadAfter = CBORObject.FromByteArray(currentPayload);
        issuerAuth.set(2, payloadAfter);
        issuerSigned.set("issuerAuth", issuerAuth);
        document.set("issuerSigned", issuerSigned);
        documents.set(0, document);
        cborObject.set("documents", documents);
        byte[] bytes = cborObject.EncodeToBytes();
		return Base64.getUrlEncoder().encodeToString(bytes);
    }

    @Test
    public void test_loadAndVerifyDocumentsForVP_SignatureValidationFail() {
        VPValidator vp_validator = null;
        try {
            String vp_from_verifier = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBleBhldS5ldXJvcGEuZWMuZXVkaXcucGlkLjFsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xhtgYWGmkZnJhbmRvbVgggCpS0xCfgPmPD2zFhQNieYOwZsUPiQoHzpUCI7gWH7BoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZWlSb2RyaWd1ZXNxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhmpGZyYW5kb21YIIvNXv-shbvhLmg6RLHGDOUpKNcV9r7MocrpbX88RjQqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVnTWFyaWFuYXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYbKRmcmFuZG9tWCBOb54F3cjnU8BMqtl1Ha9mjYGSsE1G_9aBiwpCr41MKmhkaWdlc3RJRAFsZWxlbWVudFZhbHVl2QPsajIwMDEtMDMtMTlxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWGCkZnJhbmRvbVggCVL_ymTwJKhV0WktqqsFnK3ysLDCHM4ADSIfiDwsLt9oZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFh1pGZyYW5kb21YIFdIw3WsKTt_uFlXa8sRmO_EiNCwW-uU35bM2Pwx2x7IaGRpZ2VzdElEB2xlbGVtZW50VmFsdWVvVGVzdCBQSUQgaXNzdWVycWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYZqRmcmFuZG9tWCD1ZWNZV_hDbwzWvokzSsB3LQYW7GPaEQLSxD_qXCKNpWhkaWdlc3RJRAJsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWppc3N1ZXJBdXRohEOhASahGCFZAugwggLkMIICaqADAgECAhRyMm32Ywiae1APjD8mpoXLwsLSyjAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjMwOTAyMTc0MjUxWhcNMjQxMTI1MTc0MjUwWjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQR81BwtG6ZqjrWQYWWw5pPeGxzlr3ptXIr3ftI93rJ_KvC9TAgqJTakJAj2nV4yQGLJl0tw-PhwfbHDrIYsWKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBSB7_ScXIMKUKZGvvdQeFpTPj_YmzAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNoADBlAjBF-tqi7y2VU-u0iETYZBrQKp46jkord9ri9B55Xy8tkJsD8oEJlGtOLZKDrX_BoYUCMQCbnk7tUBCfXw63ACzPmLP-5BFAfmXuMPsBBL7Wc4Lqg94fXMSI5hAXZAEyJ0NATQpZAl3YGFkCWKZnZG9jVHlwZXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTAzLTE0VDEyOjQ1OjU4Wml2YWxpZEZyb23AdDIwMjQtMDMtMTRUMTI6NDU6NThaanZhbGlkVW50aWzAdDIwMjQtMDYtMTJUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6F4GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMagAWCAYu8laQ2gSMxNaN9U5QHjVYRM4YmsH5IjmZ78A_ko5rgFYIITEUHYCkJin4kegSfhfywqmIulzV64aaN4bBB_fFmtwAlggX3ZenlNuZ82FwTJ6B3pXHNRN2rPPp-_MzM9UcRAbNFMDWCBjfPdUXpQQrzl547MjZ80ZSPaCkKoJmoWTNhlEwoodjQRYIG1U-AMrIHwCA1UI9rcSSOvQtVahbGSaiV1DivEGwpUoBVggi-SxcXysAZwlghLqnrImAOqzKBTEqrWfGStpyeytf80GWCA8HQSd-zlLhWSPrEaZKcubpVCZ9CzbwTphuSEj1fKUAgdYIA_8siSHso4_-z4RE4rH4mHLyQvaQgRxUeEQ8409FVMIbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggU8-tu3KhBhsN4j8hEnytHCvFSRY7fZa1ZBZ85FDhWOsiWCAjoQopDY8VYUFL9V5OOs_BCuanfHstARFcBSCYSjLuIm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAB0EIHqYq27qIkuDxAUKGsgq91adUAp2n3CiqRnJmmV_nJHO5cs6bS4vEkLfuAeZeoYBNq01ZXPsr0TRfizx8B2xkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQFcqp8k7g4ai3Gis3RdmuJJH6sFxCEf7OkTYUC07wMSShIqyG26OpRtgL_a8-8oXbteNIxp3TMKS_Sl5npIWdCtmc3RhdHVzAA";
            String vp_token = changeSignatureValue(vp_from_verifier);

            String presentation_definition_id = "32f54163-7166-48f1-93d8-ff217bdb0653";
            String presentation_definition_input_descriptors_id = "eudi_pid";

            JSONObject vp_json_object = setVPTokenInString(vp_token, presentation_definition_id,
                    presentation_definition_input_descriptors_id);
            vp_validator = new VPValidator(vp_json_object, this.trustedIssuersCertificatesProperties);
        } catch (Exception e) {
            Assert.assertNull(e);
        }

        Assert.assertNotNull(vp_validator);

        // Act & Assert
        MDoc document = null;
        try {
            Map<Integer, String> logs = new HashMap<>();
            document = vp_validator.loadAndVerifyDocumentForVP(logs);
        } catch (Exception e) {
            Assert.assertNotNull(e);
            Assert.assertEquals(VerifiablePresentationVerificationException.class, e.getClass());
			assert e instanceof VerifiablePresentationVerificationException;
			VerifiablePresentationVerificationException exp = (VerifiablePresentationVerificationException) e;
            Assert.assertEquals(VerifiablePresentationVerificationException.Signature, exp.getType());
            Assert.assertEquals(
                    "Verification of the Verifiable Presentation Failed: The IssuerAuth Signature is not valid.",
                    e.getMessage());
        }
        Assert.assertNull(document);
    }

    @Test
    public void test_loadAndVerifyDocumentsForVP_SignatureValidationFail_PayloadChanged() {
        VPValidator vp_validator = null;
        try {
            String vp_from_verifier = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBleBhldS5ldXJvcGEuZWMuZXVkaXcucGlkLjFsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xhtgYWGmkZnJhbmRvbVgggCpS0xCfgPmPD2zFhQNieYOwZsUPiQoHzpUCI7gWH7BoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZWlSb2RyaWd1ZXNxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhmpGZyYW5kb21YIIvNXv-shbvhLmg6RLHGDOUpKNcV9r7MocrpbX88RjQqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVnTWFyaWFuYXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYbKRmcmFuZG9tWCBOb54F3cjnU8BMqtl1Ha9mjYGSsE1G_9aBiwpCr41MKmhkaWdlc3RJRAFsZWxlbWVudFZhbHVl2QPsajIwMDEtMDMtMTlxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWGCkZnJhbmRvbVggCVL_ymTwJKhV0WktqqsFnK3ysLDCHM4ADSIfiDwsLt9oZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFh1pGZyYW5kb21YIFdIw3WsKTt_uFlXa8sRmO_EiNCwW-uU35bM2Pwx2x7IaGRpZ2VzdElEB2xlbGVtZW50VmFsdWVvVGVzdCBQSUQgaXNzdWVycWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYZqRmcmFuZG9tWCD1ZWNZV_hDbwzWvokzSsB3LQYW7GPaEQLSxD_qXCKNpWhkaWdlc3RJRAJsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWppc3N1ZXJBdXRohEOhASahGCFZAugwggLkMIICaqADAgECAhRyMm32Ywiae1APjD8mpoXLwsLSyjAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjMwOTAyMTc0MjUxWhcNMjQxMTI1MTc0MjUwWjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQR81BwtG6ZqjrWQYWWw5pPeGxzlr3ptXIr3ftI93rJ_KvC9TAgqJTakJAj2nV4yQGLJl0tw-PhwfbHDrIYsWKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBSB7_ScXIMKUKZGvvdQeFpTPj_YmzAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNoADBlAjBF-tqi7y2VU-u0iETYZBrQKp46jkord9ri9B55Xy8tkJsD8oEJlGtOLZKDrX_BoYUCMQCbnk7tUBCfXw63ACzPmLP-5BFAfmXuMPsBBL7Wc4Lqg94fXMSI5hAXZAEyJ0NATQpZAl3YGFkCWKZnZG9jVHlwZXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTAzLTE0VDEyOjQ1OjU4Wml2YWxpZEZyb23AdDIwMjQtMDMtMTRUMTI6NDU6NThaanZhbGlkVW50aWzAdDIwMjQtMDYtMTJUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6F4GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMagAWCAYu8laQ2gSMxNaN9U5QHjVYRM4YmsH5IjmZ78A_ko5rgFYIITEUHYCkJin4kegSfhfywqmIulzV64aaN4bBB_fFmtwAlggX3ZenlNuZ82FwTJ6B3pXHNRN2rPPp-_MzM9UcRAbNFMDWCBjfPdUXpQQrzl547MjZ80ZSPaCkKoJmoWTNhlEwoodjQRYIG1U-AMrIHwCA1UI9rcSSOvQtVahbGSaiV1DivEGwpUoBVggi-SxcXysAZwlghLqnrImAOqzKBTEqrWfGStpyeytf80GWCA8HQSd-zlLhWSPrEaZKcubpVCZ9CzbwTphuSEj1fKUAgdYIA_8siSHso4_-z4RE4rH4mHLyQvaQgRxUeEQ8409FVMIbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggU8-tu3KhBhsN4j8hEnytHCvFSRY7fZa1ZBZ85FDhWOsiWCAjoQopDY8VYUFL9V5OOs_BCuanfHstARFcBSCYSjLuIm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAB0EIHqYq27qIkuDxAUKGsgq91adUAp2n3CiqRnJmmV_nJHO5cs6bS4vEkLfuAeZeoYBNq01ZXPsr0TRfizx8B2xkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQFcqp8k7g4ai3Gis3RdmuJJH6sFxCEf7OkTYUC07wMSShIqyG26OpRtgL_a8-8oXbteNIxp3TMKS_Sl5npIWdCtmc3RhdHVzAA";
            String vp_token = changePayloadValue(vp_from_verifier);

            String presentation_definition_id = "32f54163-7166-48f1-93d8-ff217bdb0653";
            String presentation_definition_input_descriptors_id = "eudi_pid";

            JSONObject vp_json_object = setVPTokenInString(vp_token, presentation_definition_id,
                    presentation_definition_input_descriptors_id);
            vp_validator = new VPValidator(vp_json_object, this.trustedIssuersCertificatesProperties);
        } catch (Exception e) {
            Assert.assertNull(e);
        }

        Assert.assertNotNull(vp_validator);

        // Act & Assert
        MDoc document = null;
        try {
            Map<Integer, String> logs = new HashMap<>();
            document = vp_validator.loadAndVerifyDocumentForVP(logs);
        } catch (Exception e) {
            Assert.assertNotNull(e);
            Assert.assertEquals(VerifiablePresentationVerificationException.class, e.getClass());
			assert e instanceof VerifiablePresentationVerificationException;
			VerifiablePresentationVerificationException exp = (VerifiablePresentationVerificationException) e;
            Assert.assertEquals(VerifiablePresentationVerificationException.Signature, exp.getType());
            Assert.assertEquals(
                    "Verification of the Verifiable Presentation Failed: The IssuerAuth Signature is not valid.",
                    e.getMessage());
        }
        Assert.assertNull(document);
    }

    // Verify Integrity Fail
    private String changeNamespaceInDocuments(String vp_token, String docType, byte[] newNameSpaceValue)
            throws JSONException {
        byte[] vp_token_bytes = Base64.getUrlDecoder().decode(vp_token);
        CBORObject vp_token_cbor = CBORObject.DecodeFromBytes(vp_token_bytes, CBOREncodeOptions.Default);
        CBORObject documents_cbor = vp_token_cbor.get("documents");
        CBORObject document_cbor = documents_cbor.get(0);
        CBORObject issuerSigned_cbor = document_cbor.get("issuerSigned");
        CBORObject nameSpaces_cbor = issuerSigned_cbor.get("nameSpaces");
        CBORObject docType_cbor = nameSpaces_cbor.get(docType);

        CBORObject nemNameSpaceValue_cbor = CBORObject.DecodeFromBytes(newNameSpaceValue);

        docType_cbor.set(0, nemNameSpaceValue_cbor);
        nameSpaces_cbor.set(docType, docType_cbor);
        issuerSigned_cbor.set("nameSpaces", nameSpaces_cbor);
        document_cbor.set("issuerSigned", issuerSigned_cbor);
        documents_cbor.set(0, document_cbor);
        vp_token_cbor.set("documents", documents_cbor);
        byte[] bytes = vp_token_cbor.EncodeToBytes();
		return Base64.getUrlEncoder().encodeToString(bytes);
    }

    @Test
    public void test_loadAndVerifyDocumentsForVP_IntegrityValidationFail() {
        VPValidator vp_validator = null;
        try {
            String vp_from_verifier = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBleBhldS5ldXJvcGEuZWMuZXVkaXcucGlkLjFsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xhtgYWGmkZnJhbmRvbVgggCpS0xCfgPmPD2zFhQNieYOwZsUPiQoHzpUCI7gWH7BoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZWlSb2RyaWd1ZXNxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhmpGZyYW5kb21YIIvNXv-shbvhLmg6RLHGDOUpKNcV9r7MocrpbX88RjQqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVnTWFyaWFuYXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYbKRmcmFuZG9tWCBOb54F3cjnU8BMqtl1Ha9mjYGSsE1G_9aBiwpCr41MKmhkaWdlc3RJRAFsZWxlbWVudFZhbHVl2QPsajIwMDEtMDMtMTlxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWGCkZnJhbmRvbVggCVL_ymTwJKhV0WktqqsFnK3ysLDCHM4ADSIfiDwsLt9oZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFh1pGZyYW5kb21YIFdIw3WsKTt_uFlXa8sRmO_EiNCwW-uU35bM2Pwx2x7IaGRpZ2VzdElEB2xlbGVtZW50VmFsdWVvVGVzdCBQSUQgaXNzdWVycWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYZqRmcmFuZG9tWCD1ZWNZV_hDbwzWvokzSsB3LQYW7GPaEQLSxD_qXCKNpWhkaWdlc3RJRAJsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWppc3N1ZXJBdXRohEOhASahGCFZAugwggLkMIICaqADAgECAhRyMm32Ywiae1APjD8mpoXLwsLSyjAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjMwOTAyMTc0MjUxWhcNMjQxMTI1MTc0MjUwWjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQR81BwtG6ZqjrWQYWWw5pPeGxzlr3ptXIr3ftI93rJ_KvC9TAgqJTakJAj2nV4yQGLJl0tw-PhwfbHDrIYsWKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBSB7_ScXIMKUKZGvvdQeFpTPj_YmzAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNoADBlAjBF-tqi7y2VU-u0iETYZBrQKp46jkord9ri9B55Xy8tkJsD8oEJlGtOLZKDrX_BoYUCMQCbnk7tUBCfXw63ACzPmLP-5BFAfmXuMPsBBL7Wc4Lqg94fXMSI5hAXZAEyJ0NATQpZAl3YGFkCWKZnZG9jVHlwZXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTAzLTE0VDEyOjQ1OjU4Wml2YWxpZEZyb23AdDIwMjQtMDMtMTRUMTI6NDU6NThaanZhbGlkVW50aWzAdDIwMjQtMDYtMTJUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6F4GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMagAWCAYu8laQ2gSMxNaN9U5QHjVYRM4YmsH5IjmZ78A_ko5rgFYIITEUHYCkJin4kegSfhfywqmIulzV64aaN4bBB_fFmtwAlggX3ZenlNuZ82FwTJ6B3pXHNRN2rPPp-_MzM9UcRAbNFMDWCBjfPdUXpQQrzl547MjZ80ZSPaCkKoJmoWTNhlEwoodjQRYIG1U-AMrIHwCA1UI9rcSSOvQtVahbGSaiV1DivEGwpUoBVggi-SxcXysAZwlghLqnrImAOqzKBTEqrWfGStpyeytf80GWCA8HQSd-zlLhWSPrEaZKcubpVCZ9CzbwTphuSEj1fKUAgdYIA_8siSHso4_-z4RE4rH4mHLyQvaQgRxUeEQ8409FVMIbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggU8-tu3KhBhsN4j8hEnytHCvFSRY7fZa1ZBZ85FDhWOsiWCAjoQopDY8VYUFL9V5OOs_BCuanfHstARFcBSCYSjLuIm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAB0EIHqYq27qIkuDxAUKGsgq91adUAp2n3CiqRnJmmV_nJHO5cs6bS4vEkLfuAeZeoYBNq01ZXPsr0TRfizx8B2xkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQFcqp8k7g4ai3Gis3RdmuJJH6sFxCEf7OkTYUC07wMSShIqyG26OpRtgL_a8-8oXbteNIxp3TMKS_Sl5npIWdCtmc3RhdHVzAA";
            String docType = "eu.europa.ec.eudiw.pid.1";
            String newNameSpaceValue = "2BhYaKRmcmFuZG9tWCDLrmLmeAt3bw3-AjRkuhKZpt2umKUkNKvJ3_uAPXHXomhkaWdlc3RJRAZsZWxlbWVudFZhbHVlaFJvZHJpZ3VlcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1l";
            byte[] newNameSpaceValue_bytesCBOR = Base64.getUrlDecoder().decode(newNameSpaceValue);

            String vp_token = changeNamespaceInDocuments(vp_from_verifier, docType, newNameSpaceValue_bytesCBOR);
            String presentation_definition_id = "32f54163-7166-48f1-93d8-ff217bdb0653";
            String presentation_definition_input_descriptors_id = "eudi_pid";
            JSONObject vp_json_object = setVPTokenInString(vp_token, presentation_definition_id,
                    presentation_definition_input_descriptors_id);
            vp_validator = new VPValidator(vp_json_object, this.trustedIssuersCertificatesProperties);
        } catch (Exception e) {
            Assert.assertNull(e);
        }
        Assert.assertNotNull(vp_validator);

        // Act & Assert
        MDoc document = null;
        try {
            Map<Integer, String> logs = new HashMap<>();
            document = vp_validator.loadAndVerifyDocumentForVP(logs);
        } catch (Exception e) {
            Assert.assertNotNull(e);
            Assert.assertEquals(VerifiablePresentationVerificationException.class, e.getClass());
			assert e instanceof VerifiablePresentationVerificationException;
			VerifiablePresentationVerificationException exp = (VerifiablePresentationVerificationException) e;
            Assert.assertEquals(VerifiablePresentationVerificationException.Integrity, exp.getType());
            Assert.assertEquals(
                    "Verification of the Verifiable Presentation Failed: The digest of the IssuerSignedItems are not equal to the digests in MSO.",
                    e.getMessage());
        }
        Assert.assertNull(document);
    }

    private String changeDoctypeInDocuments(String vp_token, String newDocType) throws JSONException {
        byte[] bytesCBOR = Base64.getUrlDecoder().decode(vp_token);
        CBORObject cborObject = CBORObject.DecodeFromBytes(bytesCBOR);
        CBORObject documents = cborObject.get("documents");
        CBORObject document = documents.get(0);
        document.set("docType", CBORObject.FromString(newDocType));
        documents.set(0, document);
        cborObject.set("documents", documents);
        byte[] bytes = cborObject.EncodeToBytes();
		return Base64.getUrlEncoder().encodeToString(bytes);
    }

    @Test
    public void test_loadAndVerifyDocumentsForVP_DocTypeFromDocumentsDifferent_ValidationFail() {
        VPValidator vp_validator = null;
        try {
            String vp_from_verifier = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBleBhldS5ldXJvcGEuZWMuZXVkaXcucGlkLjFsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xhtgYWGmkZnJhbmRvbVgggCpS0xCfgPmPD2zFhQNieYOwZsUPiQoHzpUCI7gWH7BoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZWlSb2RyaWd1ZXNxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhmpGZyYW5kb21YIIvNXv-shbvhLmg6RLHGDOUpKNcV9r7MocrpbX88RjQqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVnTWFyaWFuYXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYbKRmcmFuZG9tWCBOb54F3cjnU8BMqtl1Ha9mjYGSsE1G_9aBiwpCr41MKmhkaWdlc3RJRAFsZWxlbWVudFZhbHVl2QPsajIwMDEtMDMtMTlxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWGCkZnJhbmRvbVggCVL_ymTwJKhV0WktqqsFnK3ysLDCHM4ADSIfiDwsLt9oZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFh1pGZyYW5kb21YIFdIw3WsKTt_uFlXa8sRmO_EiNCwW-uU35bM2Pwx2x7IaGRpZ2VzdElEB2xlbGVtZW50VmFsdWVvVGVzdCBQSUQgaXNzdWVycWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYZqRmcmFuZG9tWCD1ZWNZV_hDbwzWvokzSsB3LQYW7GPaEQLSxD_qXCKNpWhkaWdlc3RJRAJsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWppc3N1ZXJBdXRohEOhASahGCFZAugwggLkMIICaqADAgECAhRyMm32Ywiae1APjD8mpoXLwsLSyjAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjMwOTAyMTc0MjUxWhcNMjQxMTI1MTc0MjUwWjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQR81BwtG6ZqjrWQYWWw5pPeGxzlr3ptXIr3ftI93rJ_KvC9TAgqJTakJAj2nV4yQGLJl0tw-PhwfbHDrIYsWKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBSB7_ScXIMKUKZGvvdQeFpTPj_YmzAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNoADBlAjBF-tqi7y2VU-u0iETYZBrQKp46jkord9ri9B55Xy8tkJsD8oEJlGtOLZKDrX_BoYUCMQCbnk7tUBCfXw63ACzPmLP-5BFAfmXuMPsBBL7Wc4Lqg94fXMSI5hAXZAEyJ0NATQpZAl3YGFkCWKZnZG9jVHlwZXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTAzLTE0VDEyOjQ1OjU4Wml2YWxpZEZyb23AdDIwMjQtMDMtMTRUMTI6NDU6NThaanZhbGlkVW50aWzAdDIwMjQtMDYtMTJUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6F4GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMagAWCAYu8laQ2gSMxNaN9U5QHjVYRM4YmsH5IjmZ78A_ko5rgFYIITEUHYCkJin4kegSfhfywqmIulzV64aaN4bBB_fFmtwAlggX3ZenlNuZ82FwTJ6B3pXHNRN2rPPp-_MzM9UcRAbNFMDWCBjfPdUXpQQrzl547MjZ80ZSPaCkKoJmoWTNhlEwoodjQRYIG1U-AMrIHwCA1UI9rcSSOvQtVahbGSaiV1DivEGwpUoBVggi-SxcXysAZwlghLqnrImAOqzKBTEqrWfGStpyeytf80GWCA8HQSd-zlLhWSPrEaZKcubpVCZ9CzbwTphuSEj1fKUAgdYIA_8siSHso4_-z4RE4rH4mHLyQvaQgRxUeEQ8409FVMIbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggU8-tu3KhBhsN4j8hEnytHCvFSRY7fZa1ZBZ85FDhWOsiWCAjoQopDY8VYUFL9V5OOs_BCuanfHstARFcBSCYSjLuIm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAB0EIHqYq27qIkuDxAUKGsgq91adUAp2n3CiqRnJmmV_nJHO5cs6bS4vEkLfuAeZeoYBNq01ZXPsr0TRfizx8B2xkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQFcqp8k7g4ai3Gis3RdmuJJH6sFxCEf7OkTYUC07wMSShIqyG26OpRtgL_a8-8oXbteNIxp3TMKS_Sl5npIWdCtmc3RhdHVzAA";
            String vp_token = changeDoctypeInDocuments(vp_from_verifier, "eu.europa.ec.eudiw.pid.2");
            String presentation_definition_id = "32f54163-7166-48f1-93d8-ff217bdb0653";
            String presentation_definition_input_descriptors_id = "eudi_pid";

            JSONObject vp_json_object = setVPTokenInString(vp_token, presentation_definition_id,
                    presentation_definition_input_descriptors_id);
            vp_validator = new VPValidator(vp_json_object, this.trustedIssuersCertificatesProperties);
        } catch (Exception e) {
            Assert.assertNull(e);
        }
        Assert.assertNotNull(vp_validator);

        // Act & Assert
        MDoc document = null;
        try {
            Map<Integer, String> logs = new HashMap<>();
            document = vp_validator.loadAndVerifyDocumentForVP(logs);
        } catch (Exception e) {
            Assert.assertNotNull(e);
            Assert.assertEquals(VerifiablePresentationVerificationException.class, e.getClass());
			assert e instanceof VerifiablePresentationVerificationException;
			VerifiablePresentationVerificationException exp = (VerifiablePresentationVerificationException) e;
            Assert.assertEquals(VerifiablePresentationVerificationException.Default, exp.getType());
            Assert.assertEquals(
                    "Verification of the Verifiable Presentation Failed: The DocType in the MSO is not equal to the DocType in documents.",
                    e.getMessage());
        }
        Assert.assertNull(document);
    }

    // Verify Validity Info Fail

}
