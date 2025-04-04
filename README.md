# SAML Utils

This package provides a few helpful utilities on top of
[Lite Saml](https://github.com/litesaml/lightsaml) to streamline common tasks.

## Install via Composer

`composer require theodorejb/saml-utils`

## Working with metadata

The `SamlMetadata` class simplifies getting data from Identity Provider metadata.
Call `SamlMetadata::fromXml($xml)` to create an instance from an Entity Descriptor XML string.

The underlying `EntityDescriptor` object can be accessed via a readonly `$entityDescriptor` property.

`SamlMetadata` implements the following methods:

### `getIdpCertificate()`

Returns an `X509Certificate` instance for the Identity Provider certificate.

### `getIdpSsoService()`

Returns the Redirect or POST `SingleSignOnService` defined by the Identity Provider
for receiving a SAML request to initiate single sign-on. 

### `getIdpLogoutService()`

Returns the Redirect or POST `SingleLogoutService` defined by the Identity Provider.

## Utility methods

The `SamlUtils` class implements the following static utility methods:

### `getRequestFromGlobals(): MessageContext`

Returns an object for the SAML request or response from the global GET/POST data.

### `getMessageHttpResponse(SamlMessage $message, string $bindingType): Response`

Returns a `Symfony\Component\HttpFoundation\Response` instance for sending the SAML message.

### `validateSignature(SamlMessage $message, X509Certificate $certificate): void`

Throws an Exception if the message signature is missing or fails verification with the certificate.

### `getSubjectNameId(SamlResponse $response): string`

Returns the user identity being asserted by the identity provider.

### `getFirstAttributeStatement(SamlResponse $response): AttributeStatement|null`

Returns the first assertion attribute statement if one exists.

### `getAttributeStatementValue(AttributeStatement $statement, string $name): string`

Returns the assertion attribute value for the specified attribute name.
Throws an exception if the attribute doesn't exist.

### `getResponseAttributeValue(SamlResponse $response, string $name): string`

Same as `getAttributeStatementValue()`, but can be used directly from
a `SamlResponse` rather than an `AttributeStatement`.
