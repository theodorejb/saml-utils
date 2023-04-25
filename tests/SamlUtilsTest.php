<?php

namespace theodorejb\SamlUtils\Tests;

use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Protocol\AuthnRequest;
use LightSaml\SamlConstants;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use theodorejb\SamlUtils\SamlUtils;

class SamlUtilsTest extends TestCase
{
    public function testGetMessageHttpResponse(): void
    {
        $authnRequest = (new AuthnRequest())
            ->setAssertionConsumerServiceURL('https://sp.com/acs')
            ->setProtocolBinding(SamlConstants::BINDING_SAML2_HTTP_POST)
            ->setID('_4173ed5ed704c26e36241d0dfe0f471ce04b561a4f')
            ->setIssueInstant(new \DateTime('2023-04-24 16:00', new \DateTimeZone('UTC')))
            ->setDestination('https://example.com/idp/profile/SAML2/Redirect/SSO')
            ->setIssuer(new Issuer('https://some.entity.id'))
        ;

        $expected = 'https://example.com/idp/profile/SAML2/Redirect/SSO?SAMLRequest=fZFBb8IwDIXv%2BxVV7jRpCSBFpYiNw5CYQLTbYZcpJO6I1CZdnCL271dgbJyQfLLs975nZ7NjU0cH8GicnZIkZmSWP2TzLuztFr46wBD1ExanpPNWOIkGhZUNoAhKFPOXlUhjJlrvglOuJtFyMSUfPJkMQY9ATxhX6RiG45QnmukKWMUniQLGd6NxInlForerd6%2FTryN2sLQYpA19i6XDAeODlJfJWDDW1zuJFj2UsTKct%2FYhtCgohaNs2hpi5RpqdEt7osrUQE%2BIKd2CNh5UoEWxJtHml%2FbRWG3s5%2F1ou8sQiuey3Aw266Ik0RwR%2FMn%2FyVnsGvAF%2BINR8Lpd%2FRNhe4aRCkmeoWxqcQ7nL%2FcUp859Z3l1IfmfpmsgBhtM%2BI6NzuiNbJ7R26%2FlDz8%3D';
        /** @var RedirectResponse $response */
        $response = SamlUtils::getMessageHttpResponse($authnRequest, SamlConstants::BINDING_SAML2_HTTP_REDIRECT);
        $this->assertSame($expected, $response->getTargetUrl());
    }
}
