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

namespace Mastercard.Developer.XMLSignVerify.Core.Utility.Context
{
    public static class Constants
    {

        public static string appHdrTagName => "urn1:AppHdr";

        public static string documentTagName => "urn:Document";

        public static string elemPrefix => "urn1";

        public static string namespaceUriAppHdr => "urn:iso:std:iso:20022:tech:xsd:head.001.001.01";

        public static string signPrefix => "Sgntr";

        public static string signPrefixTagName => "urn1:Sgntr";
    }
}
