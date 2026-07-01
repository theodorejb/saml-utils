<?php

namespace theodorejb\SamlUtils;

use GuzzleHttp\Psr7\{HttpFactory, ServerRequest};
use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Credential\{KeyHelper, X509Certificate};
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Protocol\{Response as SamlResponse, SamlMessage};
use LightSaml\Model\XmlDSig\{SignatureStringReader, SignatureXmlReader};
use Psr\Http\Message\ResponseInterface;

class SamlUtils
{
    public static function getRequestFromGlobals(): MessageContext
    {
        $request = ServerRequest::fromGlobals();
        $binding = self::getBindingFactory()->getBindingByRequest($request);
        $messageContext = new MessageContext();
        $binding->receive($request, $messageContext);
        return $messageContext;
    }

    /**
     * Returns a ResponseInterface object for sending the SAML message.
     */
    public static function getMessageHttpResponse(SamlMessage $message, string $bindingType): ResponseInterface
    {
        $context = new MessageContext();
        $context->setBindingType($bindingType);
        $context->setMessage($message);

        return self::getBindingFactory()->create($bindingType)->send($context);
    }

    /**
     * Emits a PSR-7 response to the client by sending its status line, headers, and body.
     *
     * @throws \Exception if output has already started, since the required headers can no longer be sent.
     */
    public static function sendResponse(ResponseInterface $response): void
    {
        if (headers_sent($file, $line)) {
            throw new \Exception("Cannot send SAML response: output already started at {$file}:{$line}");
        }

        $statusCode = $response->getStatusCode();
        $reasonPhrase = $response->getReasonPhrase();

        header(sprintf(
            'HTTP/%s %d%s',
            $response->getProtocolVersion(),
            $statusCode,
            $reasonPhrase === '' ? '' : ' ' . $reasonPhrase,
        ), true, $statusCode);

        foreach ($response->getHeaders() as $name => $values) {
            // Replace on the first value of each header, except Set-Cookie which must never be merged.
            $replace = strcasecmp($name, 'Set-Cookie') !== 0;

            foreach ($values as $value) {
                header("{$name}: {$value}", $replace);
                $replace = false;
            }
        }

        echo $response->getBody();
    }

    private static function getBindingFactory(): BindingFactory
    {
        $httpFactory = new HttpFactory();
        return new BindingFactory(null, $httpFactory, $httpFactory);
    }

    /**
     * @throws \Exception if the message signature is invalid
     */
    public static function validateSignature(SamlMessage $message, X509Certificate $certificate): void
    {
        $key = KeyHelper::createPublicKey($certificate);
        $signature = $message->getSignature();

        if ($signature === null) {
            $type = new \ReflectionClass($message)->getShortName();
            throw new \Exception("Missing {$type} signature");
        }

        if (!$signature instanceof SignatureXmlReader && !$signature instanceof SignatureStringReader) {
            throw new \Exception('Message must be deserialized before signature verification');
        }

        if (!$signature->validate($key)) {
            $type = new \ReflectionClass($message)->getShortName();
            throw new \Exception("{$type} signature verification failed");
        }
    }

    public static function getSubjectNameId(SamlResponse $response): string
    {
        $assertion = $response->getFirstAssertion();

        if (!$assertion) {
            throw new \Exception('Missing response assertion');
        }

        return $assertion->getSubject()?->getNameID()?->getValue()
            ?? throw new \Exception('Missing subject name ID');
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
