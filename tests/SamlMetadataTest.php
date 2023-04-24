<?php

namespace theodorejb\SamlUtils\Tests;

use LightSaml\Builder\EntityDescriptor\SimpleEntityDescriptorBuilder;
use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Context\SerializationContext;
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
            X509Certificate::fromFile('tests/certs/saml.crt')
        );

        $entityDescriptor = $entityDescriptorBuilder->get();
        $context = new SerializationContext();
        $entityDescriptor->serialize($context->getDocument(), $context);

        return $context->getDocument()->saveXML();
    }

    public function testGetIdpSsoRedirectLocation(): void
    {
        $metadata = SamlMetadata::fromXml(self::getIdpMetadata());
        $expected = 'https://example.com/idp/profile/SAML2/Redirect/SSO';
        $this->assertSame($expected, $metadata->getIdpSsoRedirectLocation());
    }
}
