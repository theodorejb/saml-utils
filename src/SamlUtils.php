<?php

namespace theodorejb\SamlUtils;

use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Model\Protocol\SamlMessage;
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
}
