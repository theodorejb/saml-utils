<?php

namespace theodorejb\SamlUtils;

use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Context\DeserializationContext;
use LightSaml\Model\Metadata\{EntityDescriptor, SingleLogoutService, SingleSignOnService};
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

    /**
     * @deprecated Use getIdpSsoService() method instead.
     */
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

    /**
     * @deprecated Use getIdpLogoutService() method instead.
     */
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
