<?php

namespace theodorejb\SamlUtils\Tests;

use GuzzleHttp\Psr7\ServerRequest;
use LightSaml\Binding\HttpRedirectBinding;
use LightSaml\Context\Model\DeserializationContext;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Credential\{KeyHelper, X509Certificate};
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Metadata\{EntityDescriptor, SingleLogoutService};
use LightSaml\Model\Protocol\{AuthnRequest, LogoutRequest, LogoutResponse, SamlMessage};
use LightSaml\SamlConstants;
use PHPUnit\Framework\TestCase;
use theodorejb\SamlUtils\{SamlUtils, ServiceProvider};

class ServiceProviderTest extends TestCase
{
    private static function getServiceProvider(): ServiceProvider
    {
        return new ServiceProvider(
            'https://sp.com/saml',
            'https://sp.com/saml/acs',
            'https://sp.com/saml/sls',
            X509Certificate::fromFile('tests/certs/saml.crt'),
            KeyHelper::createPrivateKey('tests/certs/saml.pem', '', true),
        );
    }

    /**
     * Sends the message via the HTTP-Redirect binding and receives it as the IdP would.
     */
    private static function sendAndReceive(SamlMessage $message): SamlMessage
    {
        $response = SamlUtils::getMessageHttpResponse($message, SamlConstants::BINDING_SAML2_HTTP_REDIRECT);
        $request = new ServerRequest('GET', $response->getHeaderLine('Location'));
        return new HttpRedirectBinding()->receive($request, new MessageContext());
    }

    public function testGetMetadataXml(): void
    {
        $sp = self::getServiceProvider();

        $deserializeContext = new DeserializationContext();
        $document = $deserializeContext->getDocument();
        $this->assertNotNull($document);
        $document->loadXML($sp->getMetadataXml());
        $node = $document->firstChild;
        $this->assertNotNull($node);

        $entityDescriptor = new EntityDescriptor();
        $entityDescriptor->deserialize($node, $deserializeContext);

        $this->assertSame('https://sp.com/saml', $entityDescriptor->getEntityID());

        $spDescriptor = $entityDescriptor->getFirstSpSsoDescriptor();
        $this->assertNotNull($spDescriptor);
        $this->assertTrue($spDescriptor->getAuthnRequestsSigned());
        $this->assertTrue($spDescriptor->getWantAssertionsSigned());
        $this->assertSame($sp->certificate->getData(), $spDescriptor->getFirstKeyDescriptor()?->getCertificate()?->getData());

        $acs = $spDescriptor->getFirstAssertionConsumerService(SamlConstants::BINDING_SAML2_HTTP_POST);
        $this->assertNotNull($acs);
        $this->assertSame('https://sp.com/saml/acs', $acs->getLocation());

        $sls = $spDescriptor->getFirstSingleLogoutService(SamlConstants::BINDING_SAML2_HTTP_REDIRECT);
        $this->assertNotNull($sls);
        $this->assertSame('https://sp.com/saml/sls', $sls->getLocation());
    }

    public function testCreateAuthnRequest(): void
    {
        $sp = self::getServiceProvider();
        $message = self::sendAndReceive($sp->createAuthnRequest('https://idp.com/sso', 'some-state'));

        $this->assertInstanceOf(AuthnRequest::class, $message);
        SamlUtils::validateSignature($message, $sp->certificate);
        $this->assertSame('https://idp.com/sso', $message->getDestination());
        $this->assertSame('https://sp.com/saml', $message->getIssuer()?->getValue());
        $this->assertSame('https://sp.com/saml/acs', $message->getAssertionConsumerServiceURL());
        $this->assertSame(SamlConstants::BINDING_SAML2_HTTP_POST, $message->getProtocolBinding());
        $this->assertSame('some-state', $message->getRelayState());
    }

    public function testCreateLogoutResponse(): void
    {
        $sp = self::getServiceProvider();
        $sloService = new SingleLogoutService('https://idp.com/slo', SamlConstants::BINDING_SAML2_HTTP_REDIRECT);
        $request = new LogoutRequest()
            ->setID('_logout_request_id')
            ->setIssuer(new Issuer('https://idp.com'))
            ->setRelayState('some-state');

        $message = self::sendAndReceive($sp->createLogoutResponse($sloService, $request));

        $this->assertInstanceOf(LogoutResponse::class, $message);
        SamlUtils::validateSignature($message, $sp->certificate);
        $this->assertSame('_logout_request_id', $message->getInResponseTo());
        $this->assertSame(SamlConstants::STATUS_SUCCESS, $message->getStatus()?->getStatusCode()?->getValue());
        $this->assertSame('https://idp.com/slo', $message->getDestination()); // falls back to Location
        $this->assertSame('https://sp.com/saml', $message->getIssuer()?->getValue());
        $this->assertSame('some-state', $message->getRelayState());

        $sloService->setResponseLocation('https://idp.com/slo/response');
        $message = $sp->createLogoutResponse($sloService, $request);
        $this->assertSame('https://idp.com/slo/response', $message->getDestination());
    }
}
