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

package eu.europa.ec.eudi.signer.sa.pdf;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import eu.europa.ec.eudi.signer.common.AccessCredentialDeniedException;
import eu.europa.ec.eudi.signer.common.FailedConnectionVerifier;
import eu.europa.ec.eudi.signer.common.TimeoutException;
import eu.europa.ec.eudi.signer.csc.payload.RedirectLinkResponse;
import eu.europa.ec.eudi.signer.sa.client.SignerClient;
import eu.europa.ec.eudi.signer.sa.client.ClientContext;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;

import javax.imageio.ImageIO;

import java.awt.Color;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;

/**
 * Extracts content and adds signature to PDF
 * Taken from the pdfbox examples
 */
public class PdfSupport {

    private final SignerClient signer;

    public PdfSupport(SignerClient contentSigner) {
        this.signer = contentSigner;
    }

    /**
     * Function that allows to get a link to redirect the user to the EUDI Wallet,
     * after the authorization request to the verifier is executed
     * 
     * @return the link to redirect to the EUDI Wallet
     */
    public RedirectLinkResponse getOIDRedirectLink(String redirect_uri) {
        return this.signer.getOIDRedirectLink(redirect_uri);
    }

    public byte[] signPdfContent(String pdfName, InputStream content, String responseCode, ClientContext context)
            throws IOException, NoSuchAlgorithmException, FailedConnectionVerifier, TimeoutException,
            AccessCredentialDeniedException, Exception {
        byte[] pdfContentBytes = IOUtils.toByteArray(content);
        try {
            return signer.signHash(pdfName, pdfContentBytes, responseCode, context);
        } catch (Exception e) {
            System.out.println(e.getClass().toString());
            throw e;
        }
    }

    /**
     * Signs the given PDF file.
     *
     * @param inFile  input PDF file
     * @param outFile output PDF file
     * @throws IOException if the input file could not be read
     */
    public void signDetached(File inFile, File outFile, String responseCode) throws IOException, NoSuchAlgorithmException,
            FailedConnectionVerifier, TimeoutException, AccessCredentialDeniedException, Exception {
        if (inFile == null || !inFile.exists()) {
            throw new FileNotFoundException("Document for signing does not exist");
        }
        FileOutputStream fos = new FileOutputStream(outFile);

        PDDocument doc = null;
        try {
            doc = PDDocument.load(inFile);
            signDetached(inFile.getName(), doc, fos, responseCode);
        } finally {
            IOUtils.closeQuietly(fos);
            IOUtils.closeQuietly(doc);
        }
    }

    public void signDetached(String pdfName, PDDocument document, OutputStream output, String responseCode)
            throws IOException, NoSuchAlgorithmException,
            FailedConnectionVerifier, TimeoutException, AccessCredentialDeniedException, Exception {
        int accessPermissions = getMDPPermission(document);
        if (accessPermissions == 1) {
            throw new IllegalStateException(
                    "No changes to the document are permitted due to DocMDP transform parameters dictionary");
        }

        PDSignature signature = new PDSignature();

        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setSignDate(Calendar.getInstance());

        // Optional: certify
        if (accessPermissions == 0) {
            setMDPPermission(document, signature, 2);
        }

        ClientContext context = signer.prepCredential();

        signature.setName(context.getSubject());
        signature.setReason("Signing documents with EUDI Wallet");

        Rectangle2D humanRect = new Rectangle2D.Float(20, 10, 350, 50);
        PDRectangle rect = createSignatureRectangle(document, humanRect);
        InputStream template = createVisualSignatureTemplate(document, document.getNumberOfPages() - 1, rect,
                signature);
        try(SignatureOptions options = new SignatureOptions()){
            options.setVisualSignature(template);
            options.setPage(document.getNumberOfPages() - 1);
            document.addSignature(signature, options);
            ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(output);
            final InputStream content = externalSigning.getContent();
            byte[] cmsSignature = signPdfContent(pdfName, content, responseCode, context);
            externalSigning.setSignature(cmsSignature);
        }
    }

    // Utilities for permissions Copied from the Apache Pdf-Box examples

    /**
     * Get the access permissions granted for this document in the DocMDP transform
     * parameters
     * dictionary. Details are described in the table "Entries in the DocMDP
     * transform parameters
     * dictionary" in the PDF specification.
     *
     * @param doc document.
     * @return the permission value. 0 means no DocMDP transform parameters
     *         dictionary exists. Other
     *         return values are 1, 2 or 3. 2 is also returned if the DocMDP
     *         transform parameters dictionary
     *         is found but did not contain a /P entry, or if the value is outside
     *         the valid range.
     */
    public static int getMDPPermission(PDDocument doc) {
        COSBase base = doc.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.PERMS);
        if (base instanceof COSDictionary) {
            COSDictionary permsDict = (COSDictionary) base;
            base = permsDict.getDictionaryObject(COSName.DOCMDP);
            if (base instanceof COSDictionary) {
                COSDictionary signatureDict = (COSDictionary) base;
                base = signatureDict.getDictionaryObject(COSName.REFERENCE);
                if (base instanceof COSArray) {
                    COSArray refArray = (COSArray) base;
                    for (int i = 0; i < refArray.size(); ++i) {
                        base = refArray.getObject(i);
                        if (base instanceof COSDictionary) {
                            COSDictionary sigRefDict = (COSDictionary) base;
                            if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject(COSName.TRANSFORM_METHOD))) {
                                base = sigRefDict.getDictionaryObject(COSName.TRANSFORM_PARAMS);
                                if (base instanceof COSDictionary) {
                                    COSDictionary transformDict = (COSDictionary) base;
                                    int accessPermissions = transformDict.getInt(COSName.P, 2);
                                    if (accessPermissions < 1 || accessPermissions > 3) {
                                        accessPermissions = 2;
                                    }
                                    return accessPermissions;
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }

    /**
     * Set the "modification detection and prevention" permissions granted for this
     * document in the
     * DocMDP transform parameters dictionary. Details are described in the table
     * "Entries in the
     * DocMDP transform parameters dictionary" in the PDF specification.
     *
     * @param doc               The document.
     * @param signature         The signature object.
     * @param accessPermissions The permission value (1, 2 or 3).
     * @throws IOException if a signature exists.
     */
    public static void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions)
            throws IOException {
        for (PDSignature sig : doc.getSignatureDictionaries()) {
            // "Approval signatures shall follow the certification signature if one is
            // present"
            // thus we don't care about timestamp signatures
            if (COSName.DOC_TIME_STAMP.equals(sig.getCOSObject().getItem(COSName.TYPE))) {
                continue;
            }
            if (sig.getCOSObject().containsKey(COSName.CONTENTS)) {
                throw new IOException("DocMDP transform method not allowed if an approval signature exists");
            }
        }

        COSDictionary sigDict = signature.getCOSObject();

        // DocMDP specific stuff
        COSDictionary transformParameters = new COSDictionary();
        transformParameters.setItem(COSName.TYPE, COSName.TRANSFORM_PARAMS);
        transformParameters.setInt(COSName.P, accessPermissions);
        transformParameters.setName(COSName.V, "1.2");
        transformParameters.setNeedToBeUpdated(true);

        COSDictionary referenceDict = new COSDictionary();
        referenceDict.setItem(COSName.TYPE, COSName.SIG_REF);
        referenceDict.setItem(COSName.TRANSFORM_METHOD, COSName.DOCMDP);
        referenceDict.setItem(COSName.DIGEST_METHOD, COSName.getPDFName("SHA1"));
        referenceDict.setItem(COSName.TRANSFORM_PARAMS, transformParameters);
        referenceDict.setNeedToBeUpdated(true);

        COSArray referenceArray = new COSArray();
        referenceArray.add(referenceDict);
        sigDict.setItem(COSName.REFERENCE, referenceArray);
        referenceArray.setNeedToBeUpdated(true);

        // Catalog
        COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
        COSDictionary permsDict = new COSDictionary();
        catalogDict.setItem(COSName.PERMS, permsDict);
        permsDict.setItem(COSName.DOCMDP, signature);
        catalogDict.setNeedToBeUpdated(true);
        permsDict.setNeedToBeUpdated(true);
    }

    private PDRectangle createSignatureRectangle(PDDocument doc, Rectangle2D humanRect) {
        float x = (float) humanRect.getX();
        float y = (float) humanRect.getY();
        float width = (float) humanRect.getWidth();
        float height = (float) humanRect.getHeight();
        PDPage page = doc.getPage(0);
        PDRectangle pageRect = page.getCropBox();
        PDRectangle rect = new PDRectangle();

        switch (page.getRotation()) {
            case 90:
                rect.setLowerLeftX(pageRect.getWidth() - y - height);
                rect.setUpperRightX(pageRect.getWidth() - y);
                rect.setLowerLeftY(x);
                rect.setUpperRightY(x + width);
                break;
            case 180:
                rect.setLowerLeftX(pageRect.getWidth() - x - width);
                rect.setUpperRightX(pageRect.getWidth() - x);
                rect.setLowerLeftY(pageRect.getHeight() - y - height);
                rect.setUpperRightY(pageRect.getHeight() - y);
                break;
            case 270:
                rect.setLowerLeftX(y);
                rect.setUpperRightX(y + height);
                rect.setLowerLeftY(pageRect.getHeight() - x - width);
                rect.setUpperRightY(pageRect.getHeight() - x);
                break;
            case 0:
            default:
                rect.setLowerLeftX(x);
                rect.setUpperRightX(x + width);
                rect.setLowerLeftY(y);
                rect.setUpperRightY(y + height);
                break;
        }
        return rect;
    }

    private InputStream createVisualSignatureTemplate(PDDocument srcDoc, int pageNum, PDRectangle rect,
            PDSignature signature) throws IOException {
        try (PDDocument doc = new PDDocument()) {

            PDPage page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
            doc.addPage(page);

            PDAcroForm acroForm = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);

            PDSignatureField signatureField = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            List<PDField> acroFormFields = acroForm.getFields();
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            acroFormFields.add(signatureField);

            widget.setRectangle(rect);

            PDStream stream = new PDStream(doc);
            PDFormXObject form = new PDFormXObject(stream);
            PDResources res = new PDResources();
            form.setResources(res);
            form.setFormType(1);

            PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
            float heightBox = bbox.getHeight();

            Matrix initialScale = null;
            switch (srcDoc.getPage(0).getRotation()) {
                case 90:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(),
                            bbox.getHeight() / bbox.getWidth());
                    heightBox = bbox.getWidth();
                    break;
                case 180:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(2));
                    break;
                case 270:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(),
                            bbox.getHeight() / bbox.getWidth());
                    heightBox = bbox.getWidth();
                    break;
                default:
                    break;
            }
            form.setBBox(bbox);

            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
            appearance.getCOSObject().setDirect(true);
            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
            appearance.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearance);

            loadDataToAppearanceStream(doc, appearanceStream, initialScale, heightBox, signature);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            return new ByteArrayInputStream(baos.toByteArray());
        }
    }

    public void loadDataToAppearanceStream(PDDocument doc, PDAppearanceStream appearanceStream, Matrix initialScale,
            float heightBox, PDSignature signature) throws IOException {
        File imageFile = new File("img/Symbol.png");
        try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {
            if (initialScale != null) {
                cs.transform(initialScale);
            }
            cs.saveGraphicsState();

            BufferedImage image = ImageIO.read(imageFile);
            float heightImage = image.getHeight();
            float widthImage = image.getWidth();

            float scale = heightBox / heightImage;
            float widthImageScaled = widthImage * scale;
            cs.transform(Matrix.getScaleInstance(scale, scale));
            PDImageXObject img = PDImageXObject.createFromFile(imageFile.getPath(), doc);
            cs.drawImage(img, 0, 0);
            cs.restoreGraphicsState();

            // show text
            PDFont font = PDType1Font.HELVETICA;
            float fontSize = 10;
            float leading = fontSize * 1f;

            X500Name x500Name = new X500Name(signature.getName());
            RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
            String name = IETFUtils.valueToString(cn.getFirst().getValue());

            SimpleDateFormat sdf = new SimpleDateFormat("EEEE dd MMM yyyy, HH:mm:ss z");
            String date = sdf.format(signature.getSignDate().getTime());

            cs.beginText();
            cs.setNonStrokingColor(Color.black);
            cs.newLineAtOffset(widthImageScaled + 10, heightBox - leading - 5);
            cs.setLeading(leading);
            cs.setFont(PDType1Font.HELVETICA_BOLD, fontSize);
            cs.showText(signature.getReason());
            cs.endText();

            cs.beginText();
            cs.setNonStrokingColor(Color.black);
            cs.newLineAtOffset(widthImageScaled + 10, heightBox - leading - 5);
            cs.setLeading(leading);
            cs.setFont(font, fontSize);
            cs.newLine();
            cs.showText("Signer: ");
            cs.newLine();
            cs.showText(date);
            cs.endText();

            float textWidth = PDType1Font.HELVETICA.getStringWidth("Signer: ") / 1000 * fontSize;

            cs.beginText();
            cs.setNonStrokingColor(Color.black);
            cs.newLineAtOffset(widthImageScaled + 10 + textWidth, heightBox - leading - 5);
            cs.setLeading(leading);
            cs.setFont(PDType1Font.HELVETICA_OBLIQUE, fontSize);
            cs.newLine();
            cs.showText(name);
            cs.endText();
        }
    }
}
