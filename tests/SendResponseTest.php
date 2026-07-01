<?php

namespace theodorejb\SamlUtils {
    // Intercept the SAPI calls sendResponse() makes. PHP resolves these unqualified
    // calls to the current namespace before falling back to the global functions.
    function headers_sent(?string &$file = null, ?int &$line = null): bool
    {
        return Tests\SendResponseTest::$outputStarted;
    }

    function header(string $header, bool $replace = true, int $response_code = 0): void
    {
        Tests\SendResponseTest::$sent[] = [$header, $replace];
    }
}

namespace theodorejb\SamlUtils\Tests {
    use GuzzleHttp\Psr7\Response;
    use PHPUnit\Framework\TestCase;
    use theodorejb\SamlUtils\SamlUtils;

    class SendResponseTest extends TestCase
    {
        /** @var list<array{0: string, 1: bool}> */
        public static array $sent = [];
        public static bool $outputStarted = false;

        protected function setUp(): void
        {
            self::$sent = [];
            self::$outputStarted = false;
        }

        public function testEmitsStatusLineHeadersAndBody(): void
        {
            $response = new Response(302, [
                'Location' => 'https://sp.com/acs',
                'Set-Cookie' => ['a=1', 'b=2'],
            ], 'redirecting...');

            ob_start();
            SamlUtils::sendResponse($response);
            $body = ob_get_clean();

            $this->assertSame('redirecting...', $body);
            $this->assertSame(['HTTP/1.1 302 Found', true], self::$sent[0]);
            $this->assertContains(['Location: https://sp.com/acs', true], self::$sent);
            // Set-Cookie must never replace, so earlier cookies aren't clobbered.
            $this->assertContains(['Set-Cookie: a=1', false], self::$sent);
            $this->assertContains(['Set-Cookie: b=2', false], self::$sent);
        }

        public function testThrowsWhenOutputAlreadyStarted(): void
        {
            self::$outputStarted = true;
            $this->expectException(\Exception::class);
            SamlUtils::sendResponse(new Response());
        }
    }
}
