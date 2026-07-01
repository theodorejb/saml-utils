<?php

namespace theodorejb\SamlUtils\Tests;

use LightSaml\Builder\EntityDescriptor\SimpleEntityDescriptorBuilder;
use LightSaml\Context\Model\SerializationContext;
use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Metadata\SingleLogoutService;
use LightSaml\SamlConstants;
use PHPUnit\Framework\TestCase;
use theodorejb\SamlUtils\SamlMetadata;

class SamlMetadataTest extends TestCase
{
    public static function getIdpMetadata(): string
    {
        $entityDescriptorBuilder = new SimpleEntityDescriptorBuilder(
            'https://some.entity.id',
            '',
            'https://example.com/idp/profile/SAML2/Redirect/SSO',
            X509Certificate::fromFile('tests/certs/saml.crt'),
        );

        $sls = new SingleLogoutService();
        $sls->setBinding(SamlConstants::BINDING_SAML2_HTTP_REDIRECT)
            ->setLocation('https://example.com/idp/profile/SAML2/Redirect/SLO')
            ->setResponseLocation('https://example.com/idp/profile/SAML2/Redirect/SLO');

        $entityDescriptor = $entityDescriptorBuilder->get();
        $ssoDescriptor = $entityDescriptor->getFirstIdpSsoDescriptor();

        if (!$ssoDescriptor) {
            throw new \Exception('Failed to retrieve IDP SSO descriptor');
        }

        $ssoDescriptor->addSingleLogoutService($sls);
        $context = new SerializationContext();
        $entityDescriptor->serialize($context->getDocument(), $context);

        $xml = $context->getDocument()->saveXML();
        if ($xml === false) {
            throw new \Exception('Failed to save XML');
        }
        return $xml;
    }

    public function testGetIdpSsoService(): void
    {
        $metadata = SamlMetadata::fromXml(self::getIdpMetadata());
        $expected = 'https://example.com/idp/profile/SAML2/Redirect/SSO';
        $this->assertSame($expected, $metadata->getIdpSsoService()->getLocation());
    }

    public function testGetIdpLogoutService(): void
    {
        $metadata = SamlMetadata::fromXml(self::getIdpMetadata());
        $expected = 'https://example.com/idp/profile/SAML2/Redirect/SLO';
        $this->assertSame($expected, $metadata->getIdpLogoutService()->getResponseLocation());
    }
}
