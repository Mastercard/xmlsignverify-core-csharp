
## Message Signature Verification Flow
Follow below steps in order to verify the digital signature of a message.

**Step 1: Verify that Signature node is present** 

Check for present of Signature node in the message and if absent, stop further processing of the message.

**Step 2: Identify the public key to verify the message**

KeyInfo/X509Data/X509SKI element within the Signature node contains the SKI (Subject Key Identifier) of the Signer.

The developers should ensure that the Verifier application has access to the public key from a trust store.

The developers should read X509SKI value to look up the public key from a trust store.

**Step 3: Verify the integrity of Signature content**

Considerations:

* ISO20022 rules mandate the reference nodes to follow specific URI attributes, as shown in above sections.


**Step 4: Process the message**

If the result of the signature verification is successful, the message can be used for semantic validations and processing.

