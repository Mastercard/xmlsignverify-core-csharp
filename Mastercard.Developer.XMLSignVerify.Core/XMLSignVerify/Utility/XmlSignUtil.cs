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
using Mastercard.Developer.XMLSignVerify.Core.Utility.Helper;
using Mastercard.Developer.XMLSignVerify.Core.Utility.Info;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Mastercard.Developer.XMLSignVerify.Core.Utility
{
    public static class  XmlSignUtil
    {
        public static XmlDocument Sign(XmlDocument xmlDocument, SignatureInfo signatureInfo, SignatureKeyInfo signatureKeyinfo)
        {
            var keyInfoId = "id" + Guid.NewGuid();
            var eSgntr = xmlDocument.CreateElement(Constants.elemPrefix, Constants.signPrefix, Constants.namespaceUriAppHdr);
            eSgntr.Prefix = Constants.elemPrefix;

            var xmlNodeListSignature =
                xmlDocument.GetElementsByTagName(Constants.signPrefixTagName);
            if (xmlNodeListSignature.Count > 0)
            {
                Exception exception = new Exception("This payload has already been signed.");
                throw exception;
            }

            var xmlNodeListAppHdr =
                xmlDocument.GetElementsByTagName(Constants.appHdrTagName);
            if (xmlNodeListAppHdr.Count == 0)
            {
                Exception exception = new Exception("AppHdr element not found.");
                throw exception;
            }

            var xmlElementAppHdr = (XmlElement)xmlNodeListAppHdr.Item(0);
            xmlElementAppHdr?.AppendChild(eSgntr);
            var xmlNodeListDoc = xmlDocument.GetElementsByTagName(Constants.documentTagName);
            if (xmlNodeListDoc.Count == 0)
            {
                Exception exception = new Exception("Document element not found.");
                throw exception;
            }
            var certificate = new X509Certificate2(signatureKeyinfo.skiIdBytes);
            var signedXml = new CustomIdSignedXml(xmlDocument)
            {
                SigningKey = signatureKeyinfo.privateKey
            };
            signedXml.Signature.SignedInfo.SignatureMethod = signatureInfo.signatureMethodAlgorithm;
            signedXml.Signature.SignedInfo.CanonicalizationMethod =
            signatureInfo.signatureCanonicalizationMethodAlgorithm;

            var keyInfo = new KeyInfo();
            var data = new KeyInfoX509Data(certificate, X509IncludeOption.None);
            X509ExtensionCollection x509ExtensionCollection = certificate.Extensions;
            foreach (X509Extension extension in x509ExtensionCollection)
            {
                if (extension.Oid.Value == "2.5.29.14")
                {
                    X509SubjectKeyIdentifierExtension ski = extension as X509SubjectKeyIdentifierExtension;
                    if (ski != null)
                    {
                        data.AddSubjectKeyId(ski.SubjectKeyIdentifier);
                    }
                }
            }

            keyInfo.AddClause(data);
            keyInfo.Id = keyInfoId;


            //ReferenceNode#1: Reference node for "AppHdr" node, Note URI=""  
            var reference = CreateReferenceAppHdrForSign(xmlDocument, signatureInfo);
            signedXml.AddReference(reference);

            //ReferenceNode#2: Reference node for "Document" node, Note no URI
            var referenceDoc = CreateReferenceDoc(xmlDocument, signatureInfo);
            signedXml.AddReference(referenceDoc);

            //ReferenceNode#3: Reference node for "KeyInfo" node, Note URI="#Id"
            var referenceKeyInfo = new Reference("#" + keyInfo.Id);
            var cn14Transform = new XmlDsigExcC14NTransform
            {
                Algorithm = signatureInfo.keyReferenceSignInfo.transformAlgorithm
            };
            referenceKeyInfo.AddTransform(cn14Transform);
            signedXml.AddReference(referenceKeyInfo);

            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature(); // evaluate signature
            var xmlDigitalSignature = signedXml.GetXml();
            eSgntr.AppendChild(xmlDocument.ImportNode(xmlDigitalSignature, true));
            return xmlDocument;
        }

        private static XmlNode GetAppHdrNode(XmlDocument xmlDocument)
        {
            var nodeListDoc = xmlDocument.SelectNodes("//*[local-name()='AppHdr']");
            var xmlElementDoc = nodeListDoc?.Item(0);
            return xmlElementDoc;
        }

        private static XmlNode GetDocNode(XmlDocument xmlDocument)
        {
            var nodeListDoc = xmlDocument.SelectNodes("//*[local-name()='Document']");
            var xmlElementDoc = nodeListDoc?.Item(0);
            return xmlElementDoc;
        }

        public static bool Verify(XmlDocument signedXml, AsymmetricAlgorithm publicKey)
        {
            var signedXmlFile = new SignedXml(signedXml);
            var nodeList = signedXml.SelectNodes("//*[local-name()='Signature']");

            if (nodeList != null && nodeList.Count == 0)
            {
                Exception exception = new Exception("This payload has not been signed");
                throw exception;
            }
            signedXmlFile.LoadXml((XmlElement)nodeList?[0]);
            BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Instance;
            var info = typeof(Reference).GetFields(flags);
            string refTargetTypeName = null;
            string refTargetName = null;
            foreach (var t in info)
                switch (t.Name)
                {
                    case "m_refTarget":
                        refTargetName = t.Name;
                        break;
                    case "_refTarget":
                        refTargetName = t.Name;
                        break;
                    case "m_refTargetType":
                        refTargetTypeName = t.Name;
                        break;
                    case "_refTargetType":
                        refTargetTypeName = t.Name;
                        break;
                }

            var refTargetTypeField = typeof(Reference).GetField(refTargetTypeName ?? string.Empty,
                BindingFlags.Instance | BindingFlags.NonPublic);
            var refTargetField = typeof(Reference).GetField(refTargetName ?? string.Empty,
                BindingFlags.Instance | BindingFlags.NonPublic);
            MemoryStream docStream;
            XmlNode docAppHdrNode = null;

            foreach (Reference reference in signedXmlFile.SignedInfo.References)
            {
                switch (reference.Uri)
                {
                    case null:
                        docAppHdrNode = GetDocNode(signedXml);
                        break;
                    case "":
                        docAppHdrNode = GetAppHdrNode(signedXml);
                        break;
                }


                if (string.IsNullOrEmpty(reference.Uri))
                {
                    docStream = new MemoryStream(Encoding.UTF8.GetBytes(docAppHdrNode?.OuterXml ?? string.Empty));
                    refTargetField?.SetValue(reference, docStream);
                    refTargetTypeField?.SetValue(reference, 0);
                }
            }

            return signedXmlFile.CheckSignature(publicKey);
        }

        private static Reference CreateReferenceAppHdrForSign(XmlDocument xmlDocument, SignatureInfo signatureInfo)
        {
            var nodeListAppHdr = xmlDocument.SelectNodes("//*[local-name()='AppHdr']");
            var xmlElementAppHdr = nodeListAppHdr?.Item(0) as XmlElement;
            var stringInMemoryStreamA =
                new MemoryStream(Encoding.Default.GetBytes(xmlElementAppHdr?.OuterXml ?? string.Empty));
            var referenceAppHdr = CreateReferenceAppHdr(stringInMemoryStreamA, signatureInfo);
            return referenceAppHdr;
        }

        private static Reference CreateReferenceAppHdr(MemoryStream stringInMemoryStreamA, SignatureInfo signatureInfo)
        {
            var referenceAppHdr = new Reference(stringInMemoryStreamA);
            var envelopeTransform = new XmlDsigEnvelopedSignatureTransform
            {
                Algorithm = signatureInfo.signatureExclusionTransformer
            };
            referenceAppHdr.AddTransform(envelopeTransform);
            var cn14Transform = new XmlDsigExcC14NTransform
            {
                Algorithm = signatureInfo.appHdrReferenceSignInfo.transformAlgorithm
            };
            referenceAppHdr.AddTransform(cn14Transform);
            referenceAppHdr.DigestMethod = signatureInfo.appHdrReferenceSignInfo.digestMethodAlgorithm;
            referenceAppHdr.Uri = "";
            return referenceAppHdr;
        }

        public static Reference CreateReferenceDoc(XmlDocument xmlDocument, SignatureInfo signatureInfo)
        {
            var nodeListDoc = xmlDocument.SelectNodes("//*[local-name()='Document']");
            var xmlElementDoc = nodeListDoc?.Item(0) as XmlElement;
            var stringInMemoryStream =
                new MemoryStream(Encoding.Default.GetBytes(xmlElementDoc?.OuterXml ?? string.Empty));
            var referenceDoc = new Reference(stringInMemoryStream);
            var cn14Transform = new XmlDsigExcC14NTransform
            {
                Algorithm = signatureInfo.documentReferenceSignInfo.transformAlgorithm
            };
            referenceDoc.AddTransform(cn14Transform);
            referenceDoc.DigestMethod = signatureInfo.documentReferenceSignInfo.digestMethodAlgorithm;
            referenceDoc.Uri = null;
            return referenceDoc;
        }
    }
}