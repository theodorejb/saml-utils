# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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


[2.0.0]: https://github.com/theodorejb/saml-utils/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/theodorejb/saml-utils/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/theodorejb/saml-utils/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/theodorejb/saml-utils/tree/v1.0.0
