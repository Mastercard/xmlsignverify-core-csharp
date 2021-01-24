
## Message Signing Flow 
**Step 1: Identify the private key and associated signing certificate required for signing** 

The developers should ensure that the Signer application has access to the private keys.

The private keys are stored in hardware security module with appropriate security controls, the public key of the key pair must have been shared with message Verifier.

**Step 2: Add Sgntr/Signature nodes to AppHdr**

**Step 3: Populate KeyInfo node**
* Add KeyInfo child node to the Signature parent element
* Build the X509Data sub node by populating the Subject Key Identifier (SKI) value from the signer certificate in the X509SKI sub-element
* Assign a UNIQUE_IDENTIFY_VALUE to the attribute "Id" of the KeyInfo element


Example Output XML node

```xml
<Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <!-- 4be9cab1-XXX-XXX-AAA-799362927dc3 is the UNIQUE_IDENTIFY_VALUE -->
  <KeyInfo Id="4be9cab1-XXX-XXX-AAA-799362927dc3">
    <X509Data>
      <!-- v1LWk*********tE= is the SKI value -->
      <X509SKI>v1LWk*********tE=</X509SKI>
    </X509Data>
  </KeyInfo>
</Signature>
```

**Step 4: Populate SignedInfo node**

* Add the SignedInfo node as a child to Signature node
* Add reference nodes for the following nodes to the SignedInfo node.
    - AppHdr node
    - Document node
    - KeyInfo node (child of Signature node)

Considerations:

* The signing process requires generation of digest for above 3 nodes. In the code snippets shown here, the digests are calculated during signing process, which is final step. See internal implementation of XMLSignature.sign() method. Different libraries may have their own implementation.
* XMLSignature uses the resolvers to find the relevant node for calculating the digest for each reference.
* ISO20022 rules mandate the reference nodes to follow specific URI attributes, as shown below.
    -   URI="" in reference for AppHdr node
    -   No URI in reference node for Document node
    -   URI="#Id" in reference node for KeyInfo node

Example Output XML node
```xml
<rain1:RequestPayload xmlns:rain1="http://ap.com/xsd/message/iso20022/rain.001.001.01">
  <!-- Node#1: AppHdr node, for which ReferenceNode#1 is added below -->
  <urn1:AppHdr xmlns:urn1="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
    ...
    <urn1:Sgntr>
      <Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
 
          <!-- Canonicalization Method and SignatureMethod added through XMLSignature constructor -->
          <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
          <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
 
          <!-- ReferenceNode#1: Reference node for "AppHdr" node, Note URI="" -->
          <Reference URI="">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
          </Reference>
 
          <!-- ReferenceNode#2: Reference node for "Document" node, Note no URI -->
          <Reference>
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
          </Reference>
           
          <!-- ReferenceNode#3: Reference node for "KeyInfo" node, Note URI is same as Id in Node#3 KeyInfo node -->
          <Reference URI="#65e9a001-d0b6-4b60-b36d-42f748e037ce">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
          </Reference>
        </SignedInfo>
 
        <!-- Empty SignatureValue node, later populated during signing -->
        <SignatureValue/>
        <!-- Node#3: KeyInfo node, for which ReferenceNode#3 is added above, see Id below is same as above -->
        <KeyInfo Id="65e9a001-d0b6-4b60-b36d-42f748e037ce">
          <X509Data>
            <X509SKI>zl4IvE2Sjjfnmh1oQCrUNM9gy1M=</X509SKI>
          </X509Data>
        </KeyInfo>
      </Signature>
    </urn1:Sgntr>
  </urn1:AppHdr>
   
  <!-- Node#2: Document node, for which ReferenceNode#2 is added above -->
  <urn:Document>
    ... ISO Message content
  </urn:Document> 
</rain1:RequestPayload>
```
**Step 5: Sign the message - calculating digests and populating SignatureValue node**

Once "SignedInfo" node is populated with all the references, the final step is generating digests of each reference and performing the final signing process. 

* Calculate the digests of 3 nodes and populate the digest values under Reference nodes in SignedInfo
* Perform XML Exclusive Canonicalization Transform on the "SignedInfo" node/object as a whole using the algorithm http://www.w3.org/2001/10/xml-exc-c14n#
* Sign the canonicalized "SignedInfo" object/node using the signing algorithm http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 and the private key. This step results into * * Base64 encoded string value as shown in below example.
* Populate the "Signature/SignatureValue" element with the resulting Base64 encoded string output value

Example Output XML node

```xml

<rain1:RequestPayload xmlns:rain1="http://ap.com/xsd/message/iso20022/rain.001.001.01">
  <!-- Node#1: AppHdr node, for which ReferenceNode#1 is added below -->
  <urn1:AppHdr xmlns:urn1="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
    ...
    <urn1:Sgntr>
      <Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <!-- SignedInfo node, which is transformed, the digests for 3 references calculated and then signed with the private key -->
        <SignedInfo>
          <!-- Canonicalization Method and SignatureMethod used by signing process -->
          <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
          <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
 
          <!-- ReferenceNode#1: Reference node for "AppHdr" node, Note URI="" -->
          <Reference URI="">
            ...
            <!-- DigestNode#1: Digest calculated for Node#1 and populated here -->
            <DigestValue>H3/8j/fKZhE/5K8X3A8P46na8At+SY1+hBfU25BOqrM=</DigestValue>
          </Reference>
 
          <!-- ReferenceNode#2: Reference node for "Document" node, Note no URI -->
          <Reference>
            ...
            <!-- DigestNode#2: Digest calculated for Node#2 and populated here -->
            <DigestValue>CLWJJ7dkYOouuTOVWtC4N/kO8F2LWJU03rYKL/ogqXM=</DigestValue>
          </Reference>
 
          <!-- ReferenceNode#3: Reference node for "KeyInfo" node, Note URI is same as Id in Node#3 KeyInfo node -->
          <Reference URI="#65e9a001-d0b6-4b60-b36d-42f748e037ce">
            ...
            <!-- DigestNode#3: Digest calculated for Node#3 and populated here -->
            <DigestValue>OQifBAjuJR4qDDF05DadJ3AZJCdBpgEsFbp903ksfcg=</DigestValue>
          </Reference>
 
        </SignedInfo>
 
        <!-- "SignatureValue" node, populated with the final signature after signing of "SignedInfo" node -->
        <SignatureValue>X7LBmNOhMYR+OrRvUIVQ6WCNsTFd2EV7LUzHANWo604FHhQqEdXmMoY7zHb8j+B51RQyZYQVcyl8QtEFLYgmzta2WnbwI1AybAXncyl5a5wmfjsDd94TbvYr8IEHCZCoi7gNdj7vzb7CJ87fmqXLRDnFa8f7tLuYlJOhu0S2+PprVYEkmly5QKcg5tNk/axLLTrV9FEFO07fD/+3YZOkWQU0MlQB3KXwe3z1biGYcxBKgWuZBzx6JVzwKNHAuk7NaAduT0MZpuFqwnnq59Cw/pr5AjNkLk70TEhhyRCXDTv7HTYRUTzOO9fOsrkjqMzd9GCZIIq9Fqv8si8EdzJwdw==</SignatureValue>
 
        <!-- Node#3: KeyInfo node, for which ReferenceNode#3 is added above, see Id below is same as above -->
        <KeyInfo Id="65e9a001-d0b6-4b60-b36d-42f748e037ce">
        ...
        </KeyInfo>
      </Signature>
    </urn1:Sgntr>
  </urn1:AppHdr>
   
  <!-- Node#2: Document node, for which ReferenceNode#2 is added above -->
  <urn:Document>
    ... ISO Message content
  </urn:Document> 
</rain1:RequestPayload>
```
