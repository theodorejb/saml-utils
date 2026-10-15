<?php

namespace theodorejb\SamlUtils\Tests;

use LightSaml\Context\Model\{DeserializationContext, SerializationContext};
use LightSaml\Credential\{KeyHelper, X509Certificate};
use LightSaml\{Helper, SamlConstants};
use LightSaml\Model\Assertion\{Assertion, Attribute, AttributeStatement, AudienceRestriction, AuthnContext};
use LightSaml\Model\Assertion\{AuthnStatement, Conditions, Issuer, NameID, Subject, SubjectConfirmation};
use LightSaml\Model\Assertion\SubjectConfirmationData;
use LightSaml\Model\Protocol\{AuthnRequest, Response as SamlResponse, Status, StatusCode};
use LightSaml\Model\XmlDSig\SignatureWriter;
use PHPUnit\Framework\TestCase;
use theodorejb\SamlUtils\{SamlMetadata, SamlUtils};

class SamlUtilsTest extends TestCase
{
    private static function getAuthnRequest(): AuthnRequest
    {
        return new AuthnRequest()
            ->setAssertionConsumerServiceURL('https://sp.com/acs')
            ->setProtocolBinding(SamlConstants::BINDING_SAML2_HTTP_POST)
            ->setID('_4173ed5ed704c26e36241d0dfe0f471ce04b561a4f')
            ->setIssueInstant(new \DateTime('2023-04-24 16:00', new \DateTimeZone('UTC')))
            ->setDestination('https://example.com/idp/profile/SAML2/Redirect/SSO')
            ->setIssuer(new Issuer('https://some.entity.id'))
        ;
    }

    public function testGetMessageHttpResponse(): void
    {
        $expected = 'https://example.com/idp/profile/SAML2/Redirect/SSO?SAMLRequest=fZFBb8IwDIXv%2BxVV7jRpCSBFpYiNw5CYQLTbYZcpJO6I1CZdnCL271dgbJyQfLLs975nZ7NjU0cH8GicnZIkZmSWP2TzLuztFr46wBD1ExanpPNWOIkGhZUNoAhKFPOXlUhjJlrvglOuJtFyMSUfPJkMQY9ATxhX6RiG45QnmukKWMUniQLGd6NxInlForerd6%2FTryN2sLQYpA19i6XDAeODlJfJWDDW1zuJFj2UsTKct%2FYhtCgohaNs2hpi5RpqdEt7osrUQE%2BIKd2CNh5UoEWxJtHml%2FbRWG3s5%2F1ou8sQiuey3Aw266Ik0RwR%2FMn%2FyVnsGvAF%2BINR8Lpd%2FRNhe4aRCkmeoWxqcQ7nL%2FcUp859Z3l1IfmfpmsgBhtM%2BI6NzuiNbJ7R26%2FlDz8%3D';

        $response = SamlUtils::getMessageHttpResponse(self::getAuthnRequest(), SamlConstants::BINDING_SAML2_HTTP_REDIRECT);
        $this->assertSame($expected, $response->getHeaderLine('Location'));
    }

    public function testGetRequestFromGlobals(): void
    {
        // Encode via the redirect binding to get the query string an IdP would receive.
        $response = SamlUtils::getMessageHttpResponse(self::getAuthnRequest(), SamlConstants::BINDING_SAML2_HTTP_REDIRECT);
        $queryString = (string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY);
        parse_str($queryString, $params);

        // Simulate the incoming GET request via the superglobals fromGlobals() reads.
        // Binding detection reads $_GET; the redirect binding parses $_SERVER['QUERY_STRING'].
        $originalGet = $_GET;
        $originalMethod = $_SERVER['REQUEST_METHOD'] ?? null;
        $originalQuery = $_SERVER['QUERY_STRING'] ?? null;
        $_GET = $params;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['QUERY_STRING'] = $queryString;

        try {
            $context = SamlUtils::getRequestFromGlobals();
        } finally {
            $_GET = $originalGet;
            if ($originalMethod === null) {
                unset($_SERVER['REQUEST_METHOD']);
            } else {
                $_SERVER['REQUEST_METHOD'] = $originalMethod;
            }
            if ($originalQuery === null) {
                unset($_SERVER['QUERY_STRING']);
            } else {
                $_SERVER['QUERY_STRING'] = $originalQuery;
            }
        }

        $message = $context->getMessage();
        $this->assertInstanceOf(AuthnRequest::class, $message);
        $this->assertSame('_4173ed5ed704c26e36241d0dfe0f471ce04b561a4f', $message->getID());
        $this->assertSame('https://example.com/idp/profile/SAML2/Redirect/SSO', $message->getDestination());
    }

    public function testGetResponseAttributeValue(): void
    {
        $metadataXml = SamlMetadataTest::getIdpMetadata();
        $metadata = SamlMetadata::fromXml($metadataXml);
        $response = $this->getSignedResponse();

        SamlUtils::validateSignature($response, $metadata->getIdpCertificate());
        $this->assertSame('jsmith', SamlUtils::getResponseAttributeValue($response, 'short_id'));
    }

    public function testResponseWithoutAttributeStatement(): void
    {
        $metadataXml = SamlMetadataTest::getIdpMetadata();
        $metadata = SamlMetadata::fromXml($metadataXml);
        $response = $this->getSignedResponseWithoutAttributeStatement();

        SamlUtils::validateSignature($response, $metadata->getIdpCertificate());

        $attributeStatement = SamlUtils::getFirstAttributeStatement($response);
        $this->assertNull($attributeStatement);

        $this->assertSame('some.username', SamlUtils::getSubjectNameId($response));
    }

    /**
     * Regression test for a signature bypass in lightsaml 6.0.0, where a SignatureValue
     * that isn't valid base64 made xmlseclibs 4 return -1 from verify(), which was treated as success.
     */
    public function testRejectsForgedResponseWithInvalidSignatureValue(): void
    {
        $doc = new \DOMDocument();
        $doc->loadXML(self::getResponseXml(self::getUnserializedResponse()));
        $xpath = new \DOMXPath($doc);
        $xpath->registerNamespace('ds', SamlConstants::NS_XMLDSIG);
        $xpath->registerNamespace('saml', SamlConstants::NS_ASSERTION);

        // tamper with the signed content
        self::queryElement($xpath, '//saml:NameID')->textContent = 'admin';

        // recompute the digest (no key required) so only the signature value is wrong
        $root = self::queryElement($xpath, '/*');
        $signature = self::queryElement($xpath, 'ds:Signature', $root);
        $nextSibling = $signature->nextSibling;
        $root->removeChild($signature);
        $digest = base64_encode(hash('sha256', $root->C14N(true), true));
        $root->insertBefore($signature, $nextSibling);

        self::queryElement($xpath, 'ds:SignedInfo/ds:Reference/ds:DigestValue', $signature)->textContent = $digest;
        self::queryElement($xpath, 'ds:SignatureValue', $signature)->textContent = '!!!!';

        $response = self::deserializeResponse((string) $doc->saveXML());

        // must fail on the signature itself, not the digest check
        $this->expectExceptionMessage('Unable to verify Signature');
        SamlUtils::validateSignature($response, X509Certificate::fromFile('tests/certs/saml.crt'));
    }

    private static function queryElement(\DOMXPath $xpath, string $expression, ?\DOMNode $context = null): \DOMElement
    {
        $list = $xpath->query($expression, $context);
        $node = $list ? $list->item(0) : null;

        if (!$node instanceof \DOMElement) {
            throw new \Exception("Missing {$expression} element");
        }

        return $node;
    }

    private static function getSignedResponseWithoutAttributeStatement(): SamlResponse
    {
        // response must be deserialized for signature verification
        return self::getDeserializedResponse(self::getUnserializedResponse());
    }

    private static function getSignedResponse(): SamlResponse
    {
        $response = self::getUnserializedResponse();
        $assertion = $response->getFirstAssertion();

        if (!$assertion) {
            throw new \Exception('Missing first response assertion');
        }

        $assertion->addItem(
            new AttributeStatement()
                ->addAttribute(new Attribute('f_name', 'John'))
                ->addAttribute(new Attribute('lname', 'Smith'))
                ->addAttribute(new Attribute('login_name', 'some'))
                ->addAttribute(new Attribute('user_name', 'some.username'))
                ->addAttribute(new Attribute('type', 'Staff'))
                ->addAttribute(new Attribute('short_id', 'jsmith')),
        );

        // response must be deserialized for signature verification
        return self::getDeserializedResponse($response);
    }

    private static function getResponseAssertion(): Assertion
    {
        $assertion = new Assertion();

        $assertion
            ->setId(Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setIssuer(new Issuer('https://idp.com'))
            ->setSubject(
                new Subject()
                    ->setNameID(new NameID('some.username', SamlConstants::NAME_ID_FORMAT_PERSISTENT))
                    ->addSubjectConfirmation(
                        new SubjectConfirmation()
                            ->setMethod(SamlConstants::CONFIRMATION_METHOD_BEARER)
                            ->setSubjectConfirmationData(
                                new SubjectConfirmationData()
                                    ->setInResponseTo('id_of_the_authn_request')
                                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                                    ->setRecipient('https://sp.com/acs'),
                            ),
                    ),
            )
            ->setConditions(
                new Conditions()
                    ->setNotBefore(new \DateTime())
                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                    ->addItem(
                        new AudienceRestriction(['https://sp.com/acs']),
                    ),
            )
            ->addItem(
                new AuthnStatement()
                    ->setAuthnInstant(new \DateTime('-10 MINUTE'))
                    ->setSessionIndex('_some_session_index')
                    ->setAuthnContext(
                        new AuthnContext()
                            ->setAuthnContextClassRef(SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT),
                    ),
            )
        ;

        return $assertion;
    }

    private static function getUnserializedResponse(): SamlResponse
    {
        $certificate = X509Certificate::fromFile('tests/certs/saml.crt');
        $privateKey = KeyHelper::createPrivateKey('tests/certs/saml.pem', '', true);

        $response = new SamlResponse();
        $response
            ->addAssertion(self::getResponseAssertion())
            ->setStatus(new Status(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setID(Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination('https://sp.com/acs')
            ->setIssuer(new Issuer('https://idp.com'))
            ->setSignature(new SignatureWriter($certificate, $privateKey))
        ;

        return $response;
    }

    private static function getDeserializedResponse(SamlResponse $response): SamlResponse
    {
        return self::deserializeResponse(self::getResponseXml($response));
    }

    private static function getResponseXml(SamlResponse $response): string
    {
        $serializeContext = new SerializationContext();
        $response->serialize($serializeContext->getDocument(), $serializeContext);
        $xml = $serializeContext->getDocument()->saveXML();

        if (!$xml) {
            throw new \Exception('XML response cannot be blank');
        }

        return $xml;
    }

    private static function deserializeResponse(string $xml): SamlResponse
    {
        $deserializeContext = new DeserializationContext();
        $document = $deserializeContext->getDocument();
        if (!$document) {
            throw new \Exception('Missing required deserialization document');
        }
        $document->loadXML($xml);
        $node = $document->firstChild;

        if (!$node) {
            throw new \Exception('Failed to parse XML response');
        }

        $response = new SamlResponse();
        $response->deserialize($node, $deserializeContext);
        return $response;
    }
}
