<?php

namespace theodorejb\SamlUtils;

use LightSaml\Context\Model\DeserializationContext;
use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Metadata\{EntityDescriptor, SingleLogoutService, SingleSignOnService};
use LightSaml\SamlConstants;

class SamlMetadata
{
    public function __construct(
        public readonly EntityDescriptor $entityDescriptor,
    ) {}

    public function getIdpCertificate(): X509Certificate
    {
        $ssoDescriptor = $this->entityDescriptor->getFirstIdpSsoDescriptor();

        if (!$ssoDescriptor) {
            throw new \Exception('Failed to retrieve IDP SSO descriptor');
        }

        $keyDescriptor = $ssoDescriptor->getFirstKeyDescriptor();

        if (!$keyDescriptor) {
            throw new \Exception('Failed to retrieve IDP SSO key descriptor');
        }

        $certificate = $keyDescriptor->getCertificate();
        if (!$certificate) {
            throw new \Exception('Failed to retrieve IDP SSO certificate');
        }
        return $certificate;
    }

    public function getIdpSsoService(): SingleSignOnService
    {
        $ssoDescriptor = $this->entityDescriptor->getFirstIdpSsoDescriptor();

        if (!$ssoDescriptor) {
            throw new \Exception('Failed to retrieve IDP SSO descriptor');
        }

        // prefer redirect if available since it's fastest
        $ssoService = $ssoDescriptor->getFirstSingleSignOnService(SamlConstants::BINDING_SAML2_HTTP_REDIRECT);

        if ($ssoService === null) {
            $ssoService = $ssoDescriptor->getFirstSingleSignOnService(SamlConstants::BINDING_SAML2_HTTP_POST);
        }

        if ($ssoService === null) {
            throw new \Exception('Failed to retrieve SSO service with Redirect or POST binding');
        }

        return $ssoService;
    }

    public function getIdpLogoutService(): SingleLogoutService
    {
        $ssoDescriptor = $this->entityDescriptor->getFirstIdpSsoDescriptor();

        if (!$ssoDescriptor) {
            throw new \Exception('Failed to retrieve IDP SSO descriptor');
        }

        // prefer redirect if available since it's fastest
        $logoutService = $ssoDescriptor->getFirstSingleLogoutService(SamlConstants::BINDING_SAML2_HTTP_REDIRECT);

        if ($logoutService === null) {
            $logoutService = $ssoDescriptor->getFirstSingleLogoutService(SamlConstants::BINDING_SAML2_HTTP_POST);
        }

        if ($logoutService === null) {
            throw new \Exception('Failed to retrieve logout service with Redirect or POST binding');
        }

        return $logoutService;
    }

    public static function fromXml(string $xml): self
    {
        if ($xml === '') {
            throw new \Exception('XML metadata cannot be blank');
        }

        $context = new DeserializationContext();
        $document = $context->getDocument();
        if (!$document) {
            throw new \Exception('Missing required deserialization document');
        }
        $document->loadXML($xml);
        $node = $document->firstChild;

        if (!$node) {
            throw new \Exception('Failed to parse XML metadata');
        }

        $entityDescriptor = new EntityDescriptor();
        $entityDescriptor->deserialize($node, $context);
        return new self($entityDescriptor);
    }
}
