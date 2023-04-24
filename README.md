# SAML Utils

This package provides a few classes to streamline usage of Light Saml.

## SamlMetadata

Use `SamlMetadata::fromXml(string $xml)` to create an instance from an XML string.
Includes the following methods:

### `getIdpCertificate(): X509Certificate`

Returns the Identity Provider certificate.

### `getIdpSsoRedirectLocation(): string`

Returns the redirect location defined by the Identity Provider
for receiving a SAML request to initiate single sign-on. 

## SamlResponse

Use `SamlResponse::fromXml(string $xml)` to create an instance from a SAML response message
from by an Identity Provider. Includes the following methods:

### `verify(X509Certificate $certificate): void`

Throws an exception if the SAML response cannot be successfully verified with the certificate.

### `getAttributeValue(string $name): string`

Returns the value for the specified attribute name.
Throws an exception if the attribute doesn't exist.

## SamlUtils

### `static getMessageRedirectUrl(SamlMessage $message): string`

Returns the URL to send a SamlMessage via redirect.
