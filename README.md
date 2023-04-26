# SAML Utils

This package provides a few helpful utilities on top of
[Light Saml](https://github.com/litesaml/lightsaml) to streamline common tasks.

## Install via Composer

`composer require theodorejb/saml-utils`

## Working with metadata

The `SamlMetadata` class simplifies getting data from Identity Provider metadata.
Call `SamlMetadata::fromXml($xml)` to create an instance from an Entity Descriptor XML string.

The underlying `EntityDescriptor` object can be accessed via a readonly `$entityDescriptor` property.

`SamlMetadata` implements the following methods:

### `getIdpCertificate()`

Returns an `X509Certificate` instance for the Identity Provider certificate.

### `getIdpSsoRedirectLocation()`

Returns the redirect location string defined by the Identity Provider
for receiving a SAML request to initiate single sign-on. 

### `getIdpRedirectLogoutService()`

Returns the redirect `SingleLogoutService` if defined by the Identity Provider, otherwise `null`.

## Utility methods

The `SamlUtils` class implements the following static utility methods:

### `getRequestFromGlobals()`

Returns a `MessageContext` object for the SAML request or response from the global GET/POST data.

### `getMessageHttpResponse(SamlMessage $message, string $bindingType)`

Returns a `Symfony\Component\HttpFoundation\Response` instance for sending the SAML message.

### `validateSignature(SamlMessage $message, X509Certificate $certificate)`

Throws an Exception if the message signature is missing or fails verification with the certificate.

### `getResponseAttributeValue(SamlResponse $response, string $name)`

Returns the assertion attribute value for the specified attribute name.
Throws an exception if the attribute doesn't exist.
