<?php

namespace theodorejb\SamlUtils\Tests;

use LightSaml\Credential\{KeyHelper, X509Certificate};
use LightSaml\Model\Assertion\{Assertion, Attribute, AttributeStatement, AudienceRestriction, AuthnContext, AuthnStatement};
use LightSaml\Model\Assertion\{Conditions, Issuer, NameID, Subject, SubjectConfirmation, SubjectConfirmationData};
use LightSaml\Model\Context\SerializationContext;
use LightSaml\Model\Protocol\{Response, Status, StatusCode};
use LightSaml\Model\XmlDSig\SignatureWriter;
use LightSaml\{Helper, SamlConstants};
use PHPUnit\Framework\TestCase;
use theodorejb\SamlUtils\{SamlMetadata, SamlResponse};

class SamlResponseTest extends TestCase
{
    private function getSignedResponse(): string
    {
        $certificate = X509Certificate::fromFile('tests/certs/saml.crt');
        $privateKey = KeyHelper::createPrivateKey('tests/certs/saml.pem', '', true);

        $response = new Response();
        $response
            ->addAssertion($assertion = new Assertion())
            ->setStatus(new Status(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setID(Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination('https://sp.com/acs')
            ->setIssuer(new Issuer('https://idp.com'))
            ->setSignature(new SignatureWriter($certificate, $privateKey))
        ;

        $assertion
            ->setId(Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setIssuer(new Issuer('https://idp.com'))
            ->setSubject(
                (new Subject())
                    ->setNameID(new NameID('some.username', SamlConstants::NAME_ID_FORMAT_PERSISTENT))
                    ->addSubjectConfirmation(
                        (new SubjectConfirmation())
                            ->setMethod(SamlConstants::CONFIRMATION_METHOD_BEARER)
                            ->setSubjectConfirmationData(
                                (new SubjectConfirmationData())
                                    ->setInResponseTo('id_of_the_authn_request')
                                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                                    ->setRecipient('https://sp.com/acs')
                            )
                    )
            )
            ->setConditions(
                (new Conditions())
                    ->setNotBefore(new \DateTime())
                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                    ->addItem(
                        new AudienceRestriction(['https://sp.com/acs'])
                    )
            )
            ->addItem(
                (new AttributeStatement())
                    ->addAttribute(new Attribute('f_name', 'John'))
                    ->addAttribute(new Attribute('lname', 'Smith'))
                    ->addAttribute(new Attribute('login_name', 'some'))
                    ->addAttribute(new Attribute('user_name', 'some.username'))
                    ->addAttribute(new Attribute('type', 'Staff'))
                    ->addAttribute(new Attribute('short_id', 'jsmith'))
            )
            ->addItem(
                (new AuthnStatement())
                    ->setAuthnInstant(new \DateTime('-10 MINUTE'))
                    ->setSessionIndex('_some_session_index')
                    ->setAuthnContext(
                        (new AuthnContext())
                            ->setAuthnContextClassRef(SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
                    )
            )
        ;

        $context = new SerializationContext();
        $response->serialize($context->getDocument(), $context);

        return $context->getDocument()->saveXML();
    }

    public function testGetResponseData(): void
    {
        $metadataXml = SamlMetadataTest::getIdpMetadata();
        $metadata = SamlMetadata::fromXml($metadataXml);
        $xml = self::getSignedResponse();

        $response = SamlResponse::fromXml($xml);
        $response->verify($metadata->getIdpCertificate());
        $this->assertSame('jsmith', $response->getAttributeValue('short_id'));
    }
}
