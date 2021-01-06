/* 
 * Copyright (c) 2020 Mastercard 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 * 
 *  
*/

using Mastercard.Developer.XMLSignVerify.Core.Utility.Context;
using Mastercard.Developer.XMLSignVerify.Core.Utility.Info;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Mastercard.Developer.XMLSignVerify.Core.Utility.Test
{
    [TestClass]
    public class XmlSignUtilTest
    {
        private X509Certificate2 _certificate;
        private X509Certificate2 _certificatepub;
        private AsymmetricAlgorithm _privatekey;

        private void SetUp()
        {
            var certificatefilename = @"..\..\..\resources\PrivateKeyCert.pfx";
            var certificatepassword = "1234";

            _certificate = new X509Certificate2(File.ReadAllBytes(certificatefilename), certificatepassword);
            _privatekey = _certificate.GetRSAPrivateKey();

            var publicKeyCertName = @"..\..\..\resources\Certificate.crt";
            _certificatepub = new X509Certificate2(File.ReadAllBytes(publicKeyCertName));
        }

        private XmlDocument ReadXmlDocumentFromPath(string xmlFilePath)
        {
            var xmlDocument = new XmlDocument();
            var reader = new StreamReader(xmlFilePath);
            xmlDocument.PreserveWhitespace = true;
            xmlDocument.Load(reader);
            reader.Close();
            return xmlDocument;
        }

        [TestMethod]
        //Sign the document and verify it
        public void SignAndVerifyTest()
        {
            SetUp();
            var signedDocument = GetSignedDocument();
            signedDocument.PreserveWhitespace = true;
            signedDocument.Save(@"..\..\..\resources\source-signed.xml");
            var xmlFilePath = @"..\..\..\resources\source-signed.xml";
            var signedDocumentfromdisk = ReadXmlDocumentFromPath(xmlFilePath);
            signedDocumentfromdisk.PreserveWhitespace = true;

            using var rsaKey = _certificatepub.GetRSAPublicKey();
            var result = XmlSignUtil.Verify(signedDocumentfromdisk, rsaKey);
            Assert.IsTrue(result);
        }

        [TestMethod]
        //Sign the document and then try to verify with wrong public key and assert failure in verification
        public void SignAndVerifyWithWrongPublicKeyTest()
        {
            SetUp();
            var signedDocument = GetSignedDocument();
            signedDocument.Save(@"..\..\..\resources\source-signed.xml");
            //generate wrong publickey from different certificate
            var filename = @"..\..\..\resources\wrongcertificate.crt";
            var differentcertificate = new X509Certificate2(File.ReadAllBytes(filename));
            var xmlFilePath = @"..\..\..\resources\source-signed.xml";
            var signedDocumentfromdisk = ReadXmlDocumentFromPath(xmlFilePath);
            signedDocumentfromdisk.PreserveWhitespace = true;

            using (differentcertificate.GetRSAPublicKey())
            {
                var result = XmlSignUtil.Verify(signedDocumentfromdisk, differentcertificate.PublicKey.Key);
                Assert.IsFalse(result);
            }
        }

        [TestMethod]
        //Sign the document and tamper the payload and assert failure in verification
        public void SignAndVerifyWithWhenSignedPayloadTamperedTest()
        {
            SetUp();
            var signedDocument = GetSignedDocument();
            signedDocument.Save(@"..\..\..\resources\source-signed.xml");
            var documentTagName = Constants.documentTagName;
            var nodeList = signedDocument.GetElementsByTagName(documentTagName);
            var element = (XmlElement)nodeList.Item(0);
            var newElement = signedDocument.CreateElement("TamperedElement");
            newElement.Prefix = element?.GetPrefixOfNamespace(element.NamespaceURI) ?? string.Empty;
            element?.AppendChild(newElement);
            signedDocument.Save(@"..\..\..\resources\source-tamperedsigned.xml");
            var xmlFilePath = @"..\..\..\resources\source-tamperedsigned.xml";
            var xmlDocument = ReadXmlDocumentFromPath(xmlFilePath);
            var signedDocumentfromdisk = xmlDocument;
            signedDocumentfromdisk.PreserveWhitespace = true;
            using var rsaKey = _certificatepub.GetRSAPublicKey();
            var result = XmlSignUtil.Verify(signedDocumentfromdisk, rsaKey);
            Assert.IsFalse(result);
        }

        private XmlDocument GetSignedDocument()
        {
            var referenceSignInfo = new ReferenceSignInfo
            {
                digestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256",
                transformAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
            };

            var signatureinfo = new SignatureInfo
            {
                appHdrReferenceSignInfo = referenceSignInfo,
                documentReferenceSignInfo = referenceSignInfo,
                keyReferenceSignInfo = referenceSignInfo,
                signatureExclusionTransformer = "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                signatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                signatureCanonicalizationMethodAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
            };

            var signatureKeyInfo = new SignatureKeyInfo
            {
                privateKey = _privatekey,
                skiIdBytes = _certificate.GetRawCertData()
            };

            var unsignedxml = ReadXmlDocumentFromPath(@"..\..\..\resources\source-unsigned.xml");
            return XmlSignUtil.Sign(unsignedxml, signatureinfo, signatureKeyInfo);
        }

        [TestMethod]
        //verify java signed document
        public void JavasignedVerifyTest()
        {
            var publicKeyCertName = @"..\..\..\resources\java-certificate.crt";
            var javacertificatepub = new X509Certificate2(File.ReadAllBytes(publicKeyCertName));

            var xmlFilePath = @"..\..\..\resources\java-source-signed.xml";
            var signedDocumentfromdisk = ReadXmlDocumentFromPath(xmlFilePath);
            signedDocumentfromdisk.PreserveWhitespace = true;

            using var rsaKey = javacertificatepub.GetRSAPublicKey();
            var result = XmlSignUtil.Verify(signedDocumentfromdisk, rsaKey);
            Assert.IsTrue(result);
        }
    }
}