<?php

namespace theodorejb\SamlUtils;

use LightSaml\Credential\{KeyHelper, X509Certificate};
use LightSaml\Model\Context\DeserializationContext;
use LightSaml\Model\Protocol\Response;
use LightSaml\Model\XmlDSig\SignatureXmlReader;

class SamlResponse
{
    public function __construct(
        public readonly Response $response,
    ) {
    }

    /**
     * @throws \Exception if the response signature doesn't match the certificate.
     */
    public function verify(X509Certificate $certificate): void
    {
        $key = KeyHelper::createPublicKey($certificate);

        /** @var SignatureXmlReader $signatureReader */
        $signatureReader = $this->response->getSignature();

        if (!$signatureReader->validate($key)) {
            throw new \Exception('Failed to verify response signature');
        }
    }

    public function getAttributeValue(string $name): string
    {
        $assertion = $this->response->getFirstAssertion();

        if (!$assertion) {
            throw new \Exception("Missing response assertion");
        }

        $statement = $assertion->getFirstAttributeStatement();

        if (!$statement) {
            throw new \Exception("Missing assertion attribute statement");
        }

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

    public static function fromXml(string $xml): self
    {
        if ($xml === '') {
            throw new \Exception('XML response cannot be blank');
        }

        $context = new DeserializationContext();
        $context->getDocument()->loadXML($xml);
        $node = $context->getDocument()->firstChild;

        if (!$node) {
            throw new \Exception('Failed to parse XML response');
        }

        $response = new Response();
        $response->deserialize($node, $context);
        return new self($response);
    }
}
