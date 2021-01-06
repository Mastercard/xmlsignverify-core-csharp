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

using Mastercard.Developer.XMLSignVerify.Core.Utility.Info;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;

namespace Mastercard.Developer.XMLSignVerify.Core.Utility.Test
{
    [TestClass]
    public class XmlSignVerifyPerformanceTest
    {
        private readonly SignatureInfo _signatureinfo = new();
        private readonly SignatureKeyInfo _signatureKeyInfo = new();
        private readonly Stopwatch _swsigntotal = new();
        private readonly Stopwatch _swverifytotal = new();
        private X509Certificate2 _certificate;
        private X509Certificate2 _certificatepub;
        private double _countersign;
        private double _counterverify;
        private AsymmetricAlgorithm _privatekey;
        private XmlDocument _signedxml = new();
        private double _signmilisec;
        private XmlDocument _unsignedxml = new();
        private double _verifymilisec;

        private void SetUp()
        {
            const string certificatefilename = @"..\..\..\resources\PrivateKeyCert.pfx";
            const string certificatepassword = "1234";

            _certificate = new X509Certificate2(File.ReadAllBytes(certificatefilename), certificatepassword);
            _privatekey = _certificate.GetRSAPrivateKey();

            const string publicKeyCertName = @"..\..\..\resources\Certificate.crt";
            _certificatepub = new X509Certificate2(File.ReadAllBytes(publicKeyCertName));
            var referenceSignInfo = new ReferenceSignInfo();
            referenceSignInfo.digestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
            referenceSignInfo.transformAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";


            _signatureinfo.appHdrReferenceSignInfo = referenceSignInfo;
            _signatureinfo.documentReferenceSignInfo = referenceSignInfo;
            _signatureinfo.keyReferenceSignInfo = referenceSignInfo;
            _signatureinfo.signatureExclusionTransformer = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
            _signatureinfo.signatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            _signatureinfo.signatureCanonicalizationMethodAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";


            _signatureKeyInfo.privateKey = _privatekey;
            _signatureKeyInfo.skiIdBytes = _certificate.GetRawCertData();


            _unsignedxml = ReadXmlDocumentFromPath(@"..\..\..\resources\source-unsigned.xml");
            _signedxml = ReadXmlDocumentFromPath(@"..\..\..\resources\source-signed.xml");
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

        //Sign the document and verify it
        private void SignTest()
        {
            _ = GetSignedDocument();
        }

        private void VerifyTest()
        {
            var signedDocument = new XmlDocument();
            signedDocument.LoadXml(_signedxml.OuterXml);
            signedDocument.PreserveWhitespace = true;
            var xmlSignUtil = new XmlSignUtil();
            using (var rsaKey = _certificatepub.GetRSAPublicKey())
            {
                _ = xmlSignUtil.Verify(signedDocument, rsaKey);
            }
        }

        private XmlDocument GetSignedDocument()
        {
            var xmlSignUtil = new XmlSignUtil();
            var xdoc = new XmlDocument();
            xdoc.LoadXml(_unsignedxml.OuterXml);
            var xmlDocument = xmlSignUtil.Sign(xdoc, _signatureinfo, _signatureKeyInfo);
            return xmlDocument;
        }

        [TestMethod]
        public void PerformanceTest()
        {
            SetUp();
            var signtasks = new[]
            {
                Task.Run(() => DoSign()),
                Task.Run(() => DoSign()),
                Task.Run(() => DoSign()),
                Task.Run(() => DoSign()),
                Task.Run(() => DoSign()),
                Task.Run(() => DoSign()),
                Task.Run(() => DoSign()),
                Task.Run(() => DoSign()),
                Task.Run(() => DoSign()),
                Task.Run(() => DoSign())
            };
            _swsigntotal.Start();
            Task.WaitAll(signtasks.ToArray());
            _swsigntotal.Stop();
            _signmilisec = _swsigntotal.ElapsedMilliseconds;

            var verifytasks = new[]
            {
                Task.Run(() => DoVerify()),
                Task.Run(() => DoVerify()),
                Task.Run(() => DoVerify()),
                Task.Run(() => DoVerify()),
                Task.Run(() => DoVerify()),
                Task.Run(() => DoVerify()),
                Task.Run(() => DoVerify()),
                Task.Run(() => DoVerify()),
                Task.Run(() => DoVerify()),
                Task.Run(() => DoVerify())
            };
            _swverifytotal.Start();
            Task.WaitAll(verifytasks.ToArray());
            _swverifytotal.Stop();

            _verifymilisec = _swverifytotal.ElapsedMilliseconds;

            var timeSpanSign = TimeSpan.FromMilliseconds(_signmilisec);
            var sign = string.Format("{0:D2}:{1:D2}:{2:D2}:{3:D2}", timeSpanSign.Hours, timeSpanSign.Minutes,
                timeSpanSign.Seconds, timeSpanSign.Milliseconds);
            Console.WriteLine("Total Sign RunTime=" + sign);
            Console.WriteLine("TPS Sign=" + Math.Round(_signmilisec / 10000, 2) + " milisec");

            var timeSpanVerify = TimeSpan.FromMilliseconds(_verifymilisec);
            var verify = string.Format("{0:D2}:{1:D2}:{2:D2}:{3:D2}", timeSpanVerify.Hours, timeSpanVerify.Minutes,
                timeSpanVerify.Seconds, timeSpanVerify.Milliseconds);
            Console.WriteLine("Total Verify RunTime=" + verify);
            Console.WriteLine("TPS Verify=" + Math.Round(_verifymilisec / 10000, 2) + " milisec");

            var timeSpanTotal = TimeSpan.FromMilliseconds(_verifymilisec + _signmilisec);
            var total = string.Format("{0:D2}:{1:D2}:{2:D2}:{3:D2}", timeSpanTotal.Hours, timeSpanTotal.Minutes,
                timeSpanTotal.Seconds, timeSpanTotal.Milliseconds);
            Console.WriteLine("Total RunTime " + total);
        }

        private void DoSign()
        {
            while (_countersign < 10000)
            {
                _countersign++;
                SignTest();
            }
        }

        private void DoVerify()
        {
            while (_counterverify < 10000)
            {
                _counterverify++;
                VerifyTest();
            }
        }
    }
}