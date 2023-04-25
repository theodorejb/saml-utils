<?php

namespace theodorejb\SamlUtils;

use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Context\DeserializationContext;
use LightSaml\Model\Metadata\{EntityDescriptor, SingleLogoutService};
use LightSaml\SamlConstants;

class SamlMetadata
{
    public function __construct(
        public readonly EntityDescriptor $entityDescriptor,
    ) {
    }

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

        return $keyDescriptor->getCertificate();
    }

    public function getIdpSsoRedirectLocation(): string
    {
        $ssoDescriptor = $this->entityDescriptor->getFirstIdpSsoDescriptor();

        if (!$ssoDescriptor) {
            throw new \Exception('Failed to retrieve IDP SSO descriptor');
        }

        $ssoService = $ssoDescriptor->getFirstSingleSignOnService(SamlConstants::BINDING_SAML2_HTTP_REDIRECT);

        if ($ssoService === null) {
            throw new \Exception('Failed to retrieve redirect SSO binding');
        }

        return $ssoService->getLocation();
    }

    public function getIdpRedirectLogoutService(): ?SingleLogoutService
    {
        $ssoDescriptor = $this->entityDescriptor->getFirstIdpSsoDescriptor();
        return $ssoDescriptor?->getFirstSingleLogoutService(SamlConstants::BINDING_SAML2_HTTP_REDIRECT);
    }

    public static function fromXml(string $xml): self
    {
        if ($xml === '') {
            throw new \Exception('XML metadata cannot be blank');
        }

        $context = new DeserializationContext();
        $context->getDocument()->loadXML($xml);
        $node = $context->getDocument()->firstChild;

        if (!$node) {
            throw new \Exception('Failed to parse XML metadata');
        }

        $entityDescriptor = new EntityDescriptor();
        $entityDescriptor->deserialize($node, $context);
        return new self($entityDescriptor);
    }
}
