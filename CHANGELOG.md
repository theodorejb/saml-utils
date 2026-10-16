# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [4.0.0] - 2026-10-16

### Changed
- Lite Saml ^6.0.1 is now required, which uses robrichards/xmlseclibs 4 and phpseclib 3.
  Decrypting assertions that use RSA-1.5 key transport is no longer supported,
  and projects that require xmlseclibs 3 will need to upgrade it.


## [3.0.0] - 2026-10-15

### Added
- `ServiceProvider` class, which creates SP metadata (`getMetadataXml()`), signed authentication requests
  (`createAuthnRequest()`), and signed logout responses (`createLogoutResponse()`) from one set of SP settings.
  This ensures the messages match what the metadata declares.

### Changed
- SP metadata now sets `AuthnRequestsSigned="true"` on the SP SSO descriptor,
  so IdPs can require that authentication requests are signed.

### Removed
- `SamlUtils::createSpMetadata()`. Use `ServiceProvider::getMetadataXml()` instead.


## [2.1.0] - 2026-07-20

### Changed
- `guzzlehttp/psr7` ^3.0 is now required.


## [2.0.0] - 2026-07-06

### Changed
- PHP 8.4+ is now required.
- Updated to Lite Saml 5.
- `SamlUtils::getMessageHttpResponse()` now returns a PSR-7 `ResponseInterface`, rather than a Symfony HttpFoundation `Response`.

### Added
- `SamlUtils::sendResponse(ResponseInterface $response)`. This method can be used to emit a response to the client,
  since PSR-7 response objects lack the `send()` method that was previously available on the Symfony `Response` class.
- `SamlUtils::createSpMetadata()` for generating signed Service Provider metadata XML with an HTTP-POST assertion
  consumer service and HTTP-Redirect single logout service.

### Removed
- Previously deprecated `SamlMetadata::getIdpSsoRedirectLocation()` and `SamlMetadata::getIdpRedirectLogoutService()` methods.


## [1.2.0] - 2024-10-09

### Added
- Support POST binding for SSO and logout services, via new `SamlMetadata::getIdpSsoService()`
  and `SamlMetadata::getIdpLogoutService()` methods.

### Deprecated
- `SamlMetadata::getIdpSsoRedirectLocation()` - use `getIdpSsoService()` instead.
- `SamlMetadata::getIdpRedirectLogoutService()` - use `getIdpLogoutService()` instead.


## [1.1.0] - 2023-10-11

### Added
- Three new utility methods: `SamlUtils::getSubjectNameId()`, `SamlUtils::getFirstAttributeStatement()`,
  and `SamlUtils::getAttributeStatementValue()`.


## [1.0.0] - 2023-04-26

Initial release with utility methods.


[4.0.0]: https://github.com/theodorejb/saml-utils/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/theodorejb/saml-utils/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/theodorejb/saml-utils/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/theodorejb/saml-utils/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/theodorejb/saml-utils/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/theodorejb/saml-utils/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/theodorejb/saml-utils/tree/v1.0.0
