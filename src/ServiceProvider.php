<?php

namespace theodorejb\SamlUtils;

use LightSaml\Context\Model\SerializationContext;
use LightSaml\Credential\X509Certificate;
use LightSaml\Helper;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Metadata\{AssertionConsumerService, EntityDescriptor, KeyDescriptor, SingleLogoutService, SpSsoDescriptor};
use LightSaml\Model\Protocol\{AuthnRequest, LogoutRequest, LogoutResponse, Status, StatusCode};
use LightSaml\Model\XmlDSig\SignatureWriter;
use LightSaml\SamlConstants;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * A Service Provider with an HTTP-POST assertion consumer service and HTTP-Redirect single logout service,
 * which signs every message it creates with its private key.
 */
readonly class ServiceProvider
{
    public function __construct(
        public string $entityId,
        public string $acsPostUrl,
        public string $slsRedirectUrl,
        public X509Certificate $certificate,
        public XMLSecurityKey $privateKey,
    ) {}

    /**
     * Returns SP metadata XML declaring that authentication requests are signed
     * and that assertions should be signed.
     */
    public function getMetadataXml(): string
    {
        $acs = new AssertionConsumerService();
        $acs->setIsDefault(true)
            ->setBinding(SamlConstants::BINDING_SAML2_HTTP_POST)
            ->setLocation($this->acsPostUrl);

        $sls = new SingleLogoutService();
        $sls->setBinding(SamlConstants::BINDING_SAML2_HTTP_REDIRECT)
            ->setLocation($this->slsRedirectUrl);

        $keyDescriptor = new KeyDescriptor()
            ->setUse(KeyDescriptor::USE_SIGNING)
            ->setCertificate($this->certificate);

        $spSsoDescriptor = new SpSsoDescriptor();
        $spSsoDescriptor->setAuthnRequestsSigned(true)
            ->setWantAssertionsSigned(true)
            ->addAssertionConsumerService($acs)
            ->addSingleLogoutService($sls);
        $spSsoDescriptor->addKeyDescriptor($keyDescriptor);

        $entityDescriptor = new EntityDescriptor()
            ->setID(Helper::generateID())
            ->setEntityID($this->entityId)
            ->addItem($spSsoDescriptor);

        $context = new SerializationContext();
        $entityDescriptor->serialize($context->getDocument(), $context);
        $xml = $context->getDocument()->saveXML();

        if ($xml === false) {
            throw new \Exception('Failed to serialize SP metadata');
        }

        return $xml;
    }

    /**
     * Returns a signed request asking the IdP to authenticate the user
     * and POST its response to the assertion consumer service.
     */
    public function createAuthnRequest(string $destination, ?string $relayState = null): AuthnRequest
    {
        return new AuthnRequest()
            ->setAssertionConsumerServiceURL($this->acsPostUrl)
            ->setProtocolBinding(SamlConstants::BINDING_SAML2_HTTP_POST)
            ->setID(Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination($destination)
            ->setIssuer(new Issuer($this->entityId))
            ->setRelayState($relayState)
            ->setSignature(new SignatureWriter($this->certificate, $this->privateKey));
    }

    /**
     * Returns a signed success response to the IdP's logout request.
     */
    public function createLogoutResponse(SingleLogoutService $sloService, LogoutRequest $request): LogoutResponse
    {
        // Responses go to the Location when the IdP doesn't specify a separate ResponseLocation.
        $destination = $sloService->getResponseLocation() ?? $sloService->getLocation()
            ?? throw new \Exception('Missing logout service location');

        return new LogoutResponse()
            ->setInResponseTo($request->getID() ?? throw new \Exception('Missing request ID'))
            ->setStatus(new Status(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setID(Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination($destination)
            ->setIssuer(new Issuer($this->entityId))
            ->setRelayState($request->getRelayState())
            ->setSignature(new SignatureWriter($this->certificate, $this->privateKey));
    }
}
