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

using System;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Mastercard.Developer.XMLSignVerify.Core.Utility.Helper
{
    public class CustomIdSignedXml : SignedXml
    {
        public CustomIdSignedXml(XmlDocument doc) : base(doc)
        {
            _ = doc;
        }

        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            XmlElement element;
            if (string.Compare(idValue, KeyInfo.Id, StringComparison.OrdinalIgnoreCase) == 0)
                element = KeyInfo.GetXml();
            else
                element = base.GetIdElement(document, idValue);
            return element;
        }
    }
}