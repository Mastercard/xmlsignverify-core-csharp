

## Table of Contents
- [Overview](#overview)
- [Example signed and unsigned messages](#signedunsignedmessageexample)

## Overview <a name="overview"></a>
The purpose of this document is to help developers get better understanding of how message signing and message verification can be developed in accordance to the ISO20022 rules.

This document should be read in conjunction with the Zapp Platform Digital Signature Implementation Guide for ISO20022.

Developers must note that this is only a guide to provide some reference C# code snippets for helping with implementation and don't mandate the code to be used literally, as documented.

The code snippets provided in this document use C# Library for Signing and Signature Verification implementation, other frameworks/technologies used in partners/vendor platforms may have specific implementations. They must adhere to the requirements specified in the Implementation guide.

## Example signed and unsigned messages <a name="signedunsignedmessageexample"></a>

Before going into the process of digital signing and message verification, the developer should understand how a signed and unsigned message looks like.

As shown in below example, the signed message has "Sgntr" node added as a child node under "AppHdr" node. The digital signing process adds this node.

Unsigned ISO message example

```xml
<rain1:RequestPayload xmlns:rain1="http://ap.com/xsd/message/iso20022/rain.001.001.01">
  <urn1:AppHdr xmlns:urn1="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
    <urn1:Fr>...</urn1:Fr>
    <urn1:To>...</urn1:To>
    <urn1:BizMsgIdr>AP0409201832404829384005</urn1:BizMsgIdr>
    <urn1:MsgDefIdr>rain.001.001.01</urn1:MsgDefIdr>
    <urn1:CreDt>2018-09-07T09:59:12.133Z</urn1:CreDt>
  </urn1:AppHdr>
  <urn:Document xmlns:urn="urn:iso:std:iso:20022:tech:xsd:rain.001.001.01">
    ... ISO Message content
  </urn:Document> 
</rain1:RequestPayload>
```

Signed ISO message example

```xml

<rain1:RequestPayload xmlns:rain1="http://ap.com/xsd/message/iso20022/rain.001.001.01">
  <urn1:AppHdr xmlns:urn1="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
    <urn1:Fr>...</urn1:Fr>
    <urn1:To>...</urn1:To>
    <urn1:BizMsgIdr>AP0409201832404829384005</urn1:BizMsgIdr>
    <urn1:MsgDefIdr>rain.001.001.01</urn1:MsgDefIdr>
    <urn1:CreDt>2018-09-07T09:59:12.133Z</urn1:CreDt>
    <!-- Signing process adds the following "Sgntr" node to the message -->
    <urn1:Sgntr>
      <Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
          <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
          <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
          <Reference URI="">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
            <DigestValue>H3/8j/fKZhE/5K8X3A8P46na8At+SY1+hBfU25BOqrM=</DigestValue>
          </Reference>
          <Reference URI="#65e9a001-d0b6-4b60-b36d-42f748e037ce">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
            <DigestValue>OQifBAjuJR4qDDF05DadJ3AZJCdBpgEsFbp903ksfcg=</DigestValue>
          </Reference>
          <Reference>
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
            <DigestValue>CLWJJ7dkYOouuTOVWtC4N/kO8F2LWJU03rYKL/ogqXM=</DigestValue>
          </Reference>
        </SignedInfo>
        <SignatureValue>X7LBmNOhMYR+OrRvUIVQ6WCNsTFd2EV7LUzHANWo604FHhQqEdXmMoY7zHb8j+B51RQyZYQVcyl8QtEFLYgmzta2WnbwI1AybAXncyl5a5wmfjsDd94TbvYr8IEHCZCoi7gNdj7vzb7CJ87fmqXLRDnFa8f7tLuYlJOhu0S2+PprVYEkmly5QKcg5tNk/axLLTrV9FEFO07fD/+3YZOkWQU0MlQB3KXwe3z1biGYcxBKgWuZBzx6JVzwKNHAuk7NaAduT0MZpuFqwnnq59Cw/pr5AjNkLk70TEhhyRCXDTv7HTYRUTzOO9fOsrkjqMzd9GCZIIq9Fqv8si8EdzJwdw==</SignatureValue>
        <KeyInfo Id="65e9a001-d0b6-4b60-b36d-42f748e037ce">
          <X509Data>
            <X509SKI>zl4IvE2Sjjfnmh1oQCrUNM9gy1M=</X509SKI>
          </X509Data>
        </KeyInfo>
      </Signature>
    </urn1:Sgntr>
  </urn1:AppHdr>
  <urn:Document xmlns:urn="urn:iso:std:iso:20022:tech:xsd:rain.001.001.01">
    ... ISO Message content
  </urn:Document> 
</rain1:RequestPayload>

```

Sgntr node structure

```xml

<urn1:Sgntr>
  <Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>...</SignedInfo>
    <SignatureValue>...</SignatureValue>
    <KeyInfo Id="UNIQUE_ID">...</KeyInfo>
  </Signature>
</urn1:Sgntr>

```
Signature node elements

| Node | Description |
| ---- | ----------- |
| SignedInfo | Node that contains the digests of all the other nodes in the business message. The SignedInfo is the node, which is signed using private key.|
| SignatureValue | Node that contains the final Base64 encoded signature value |
| KeyInfo | Node that contains the information about key used to signed the message. It contains SubjectKeyIdentifier in "X509SKI" element, which should be used to lookup corresponding public key to verify the message signature. |
