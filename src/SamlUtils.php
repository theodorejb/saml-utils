<?php

namespace theodorejb\SamlUtils;

use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Credential\{KeyHelper, X509Certificate};
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Protocol\{Response as SamlResponse, SamlMessage};
use LightSaml\Model\XmlDSig\{SignatureStringReader, SignatureXmlReader};
use Symfony\Component\HttpFoundation\{Request, Response};

class SamlUtils
{
    /**
     * @api
     */
    public static function getRequestFromGlobals(): MessageContext
    {
        $request = Request::createFromGlobals();
        $bindingFactory = new BindingFactory();
        $binding = $bindingFactory->getBindingByRequest($request);
        $messageContext = new MessageContext();
        $binding->receive($request, $messageContext);
        return $messageContext;
    }

    /**
     * Returns an HTTP Response object for sending the SAML message.
     */
    public static function getMessageHttpResponse(SamlMessage $message, string $bindingType): Response
    {
        $context = new MessageContext();
        $context->setBindingType($bindingType);
        $context->setMessage($message);
        $bindingFactory = new BindingFactory();

        return $bindingFactory->create($bindingType)->send($context);
    }

    /**
     * @throws \Exception if the message signature is invalid
     */
    public static function validateSignature(SamlMessage $message, X509Certificate $certificate): void
    {
        $key = KeyHelper::createPublicKey($certificate);
        $signature = $message->getSignature();

        if ($signature === null) {
            $type = (new \ReflectionClass($message))->getShortName();
            throw new \Exception("Missing {$type} signature");
        }

        if (!$signature instanceof SignatureXmlReader && !$signature instanceof SignatureStringReader) {
            throw new \Exception('Message must be deserialized before signature verification');
        }

        if (!$signature->validate($key)) {
            $type = (new \ReflectionClass($message))->getShortName();
            throw new \Exception("{$type} signature verification failed");
        }
    }

    public static function getSubjectNameId(SamlResponse $response): string
    {
        $assertion = $response->getFirstAssertion();

        if (!$assertion) {
            throw new \Exception('Missing response assertion');
        }

        return $assertion->getSubject()->getNameID()->getValue();
    }

    /**
     * Returns the first attribute statement, or null if one does not exist.
     * @throws \Exception if the response has no assertion
     */
    public static function getFirstAttributeStatement(SamlResponse $response): ?AttributeStatement
    {
        $assertion = $response->getFirstAssertion();

        if (!$assertion) {
            throw new \Exception('Missing response assertion');
        }

        return $assertion->getFirstAttributeStatement();
    }

    /**
     * Returns the specified assertion attribute value
     * @throws \Exception if the attribute doesn't exist
     */
    public static function getAttributeStatementValue(AttributeStatement $statement, string $name): string
    {
        $attribute = $statement->getFirstAttributeByName($name);

        if (!$attribute) {
            $attrNames = [];

            foreach ($statement->getAllAttributes() as $attr) {
                $attrNames[] = $attr->getName();
            }

            $validAttributes = implode(', ', $attrNames);
            throw new \Exception("Missing {$name} attribute. Valid attributes: {$validAttributes}");
        }

        $value = $attribute->getFirstAttributeValue();

        if ($value === null || $value === '') {
            throw new \Exception("Missing value for {$name} attribute");
        }

        return $value;
    }

    /**
     * Returns the specified assertion attribute value
     * @throws \Exception if the attribute doesn't exist
     */
    public static function getResponseAttributeValue(SamlResponse $response, string $name): string
    {
        $statement = self::getFirstAttributeStatement($response);

        if (!$statement) {
            throw new \Exception('Missing assertion attribute statement');
        }

        return self::getAttributeStatementValue($statement, $name);
    }
}
