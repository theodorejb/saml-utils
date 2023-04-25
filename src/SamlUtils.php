<?php

namespace theodorejb\SamlUtils;

use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Model\Context\SerializationContext;
use LightSaml\Model\Protocol\SamlMessage;
use LightSaml\SamlConstants;
use Symfony\Component\HttpFoundation\{RedirectResponse, Request};

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
     * Returns the URL to send a SamlMessage via redirect (e.g. an authentication request).
     */
    public static function getMessageRedirectUrl(SamlMessage $message): string
    {
        $serializationContext = new SerializationContext();
        $message->serialize($serializationContext->getDocument(), $serializationContext);
        $messageContext = new MessageContext();
        $messageContext->setMessage($message);

        $bindingFactory = new BindingFactory();
        $redirectBinding = $bindingFactory->create(SamlConstants::BINDING_SAML2_HTTP_REDIRECT);
        /** @var RedirectResponse $httpResponse */
        $httpResponse = $redirectBinding->send($messageContext);

        return $httpResponse->getTargetUrl();
    }
}
