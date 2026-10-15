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

## Service Provider

The `ServiceProvider` class creates metadata and messages for a Service Provider
with an HTTP-POST assertion consumer service and HTTP-Redirect single logout service.
Every message it creates is signed with the private key, so its metadata can declare
that authentication requests are signed.

```php
use LightSaml\Credential\{KeyHelper, X509Certificate};
use theodorejb\SamlUtils\ServiceProvider;

$sp = new ServiceProvider(
    entityId: 'https://sp.com/saml',
    acsPostUrl: 'https://sp.com/saml/acs',
    slsRedirectUrl: 'https://sp.com/saml/sls',
    certificate: X509Certificate::fromFile('saml.crt'),
    privateKey: KeyHelper::createPrivateKey('saml.pem', '', true),
);
```

### `getMetadataXml(): string`

Returns Service Provider metadata XML declaring that authentication requests are signed
and that assertions should be signed.

### `createAuthnRequest(string $destination, ?string $relayState = null): AuthnRequest`

Returns a signed request asking the Identity Provider to authenticate the user
and POST its response to the assertion consumer service.

### `createLogoutResponse(SingleLogoutService $sloService, LogoutRequest $request): LogoutResponse`

Returns a signed success response to the Identity Provider's logout request.
It is sent to the service's `ResponseLocation`, or its `Location` if no `ResponseLocation` is specified.
This method does not verify the logout request, so first pass it to `SamlUtils::validateSignature()`
with the Identity Provider's certificate.

## Utility methods

The `SamlUtils` class implements the following static utility methods:

### `getRequestFromGlobals(): MessageContext`

Returns an object for the SAML request or response from the global GET/POST data.

### `getMessageHttpResponse(SamlMessage $message, string $bindingType): ResponseInterface`

Returns a PSR-7 `Psr\Http\Message\ResponseInterface` instance for sending the SAML message.

### `sendResponse(ResponseInterface $response): void`

Emits a PSR-7 `Psr\Http\Message\ResponseInterface` to the client by sending its status line, headers, and body.

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
