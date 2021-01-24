[![](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/Mastercard/ap-bah-crypto-utility/blob/master/LICENSE)

## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
- [Usage](#usage)
  * [Signing the Request](#signing-request)
  * [Verifying the Request](#verifying-request)
  * [Adding the classes to Your Project](#adding-the-classes-to-your-project)

## Overview <a name="overview"></a>
This library provides reference implementation of ISO 20022 Digital Signature specification to sign and verify XML messages. 

Refer to [ISO20022 Signed Unsigned Message Examples](docs/ISO20022_Signed_Unsigned_Examples_Reference_Guide.md) for understanding the difference between a signed and unsigned message.

In a signed XML payload, you will see three reference nodes:
* Resource as URI="" - will get resolved to `AppHdr`
* Resource with no URI - will get resolved to Document
* Resource as URI="#id" - will get resolved to element as per that id value

### Compatibility <a name="compatibility"></a>
* Visual Studio 2019+ or JetBrain Rider 2020+
* Framework NET 5.0 
 
## Usage <a name="usage"></a>

### Signing the Request <a name="signing-request"></a>

`XmlSignUtil.Sign(XmlDocument xmlDocument, SignatureInfo signatureInfo, SignatureKeyInfo signatureKeyinfo)` signs the XML Document where:
* `xmlDocument` - the unsigned payload 
* `signatureInfo` - signature info which is used in signing the payload
* `signatureKeyInfo` - signature key info which holds private key and ski bytes to be set in X509 Data element

Refer to [detailed message signing flow](docs/MessageSigningFlow.md).

### Verifying the Request <a name="verifying-request"></a>

`XmlSignUtil.Verify(XmlDocument signedXml, AsymmetricAlgorithm publicKey)` verifies the signed payload where:
* `signedXml` - the signed payload
* `publicKey` - the public key

Refer to [detailed message verification flow](docs/MessageVerificationFlow.md).

### Adding the Classes to Your Project <a name="adding-the-classes-to-your-project"></a>

There are two classes:
* _XmlSignUtil.cs_
* _XmlSignUtilTest.cs_
 
_XmlSignUtil.cs_ calls below methods:
* `Sign`
* `Verify`
 
_XmlSignUtilTest.cs_ includes 4 test cases:
* Sign the document and verify it: `SignAndVerifyTest()`
* Sign the document and then try to verify with wrong public key and assert failure in verification: `SignAndVerifyWithWrongPublicKeyTest()`
* Sign the document and tamper the payload and assert failure in verification: `SignAndVerifyWithWhenSignedPayloadTamperedTest()`
* Verify a Java-signed document: `JavaSignedVerifyTest()`
