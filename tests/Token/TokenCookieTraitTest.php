<?php

declare(strict_types=1);

namespace T0mmy742\ApiAuthentication\Tests\Token;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\ApiAuthentication\Token\TokenCookieTrait;

use function gmdate;
use function time;

/**
 * @covers \T0mmy742\ApiAuthentication\Token\TokenCookieTrait
 */
class TokenCookieTraitTest extends TestCase
{
    use TokenCookieTrait;

    /** @var string[] */
    private array $cookieDomains = ['example.org'];

    public function testAdd30MinCookieToResponse(): void
    {
        $token = '8ba28a85ec598409d31ffc5e21117d0973f83040fac7599fbfd2db8edab84705';
        $domain = 'example.org';

        $response = $this->createMock(ResponseInterface::class);
        $response2 = $this->createStub(ResponseInterface::class);
        $response
            ->expects(self::once())
            ->method('withAddedHeader')
            ->with(self::isType('string'))
            ->willReturnCallback(
                function (string $name, string $value) use ($token, $domain, $response2): ResponseInterface {
                    $expires = gmdate('D, d-M-Y H:i:s e', time() + 30 * 60);
                    $expectedCookie = 'access_token=' . $token
                        . '; Expires=' . $expires
                        . '; Domain=' . $domain
                        . '; Path=' . '/'
                        . '; Secure'
                        . '; HttpOnly'
                        . '; SameSite=Strict';

                    self::assertSame($expectedCookie, $value);

                    return $response2;
                }
            );

        $newResponse = $this->add30MinCookieToResponse($response, $token, $domain);

        self::assertSame($response2, $newResponse);
    }

    public function testFromAllowedDomainRefererHeader(): void
    {
        $expectedDomain = 'example.org';
        $uri = 'https://' . $expectedDomain . '/endpoint';

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::once())
            ->method('hasHeader')
            ->with('Referer')
            ->willReturn(true);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->with('Referer')
            ->willReturn([$uri]);

        $domain = $this->fromAllowedDomains($request);

        self::assertSame($expectedDomain, $domain);
    }

    public function testFromAllowedDomainOriginHeader(): void
    {
        $expectedDomain = 'example.org';
        $uri = 'https://' . $expectedDomain . '/endpoint';

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::exactly(2))
            ->method('hasHeader')
            ->withConsecutive(['Referer'], ['Origin'])
            ->willReturnOnConsecutiveCalls(false, true);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->with('Origin')
            ->willReturn([$uri]);

        $domain = $this->fromAllowedDomains($request);

        self::assertSame($expectedDomain, $domain);
    }

    public function testFromAllowedDomainBadHeader(): void
    {
        $badUri = 'https:/e^f';

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::once())
            ->method('hasHeader')
            ->with('Referer')
            ->willReturn(true);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->with('Referer')
            ->willReturn([$badUri]);

        $domain = $this->fromAllowedDomains($request);

        self::assertNull($domain);
    }

    public function testFromAllowedDomainNoHeader(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::exactly(2))
            ->method('hasHeader')
            ->withConsecutive(['Referer'], ['Origin'])
            ->willReturnOnConsecutiveCalls(false);

        $domain = $this->fromAllowedDomains($request);

        self::assertNull($domain);
    }

    public function testFromAllowedDomainNotAllowed(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::once())
            ->method('hasHeader')
            ->with('Referer')
            ->willReturn(true);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->with('Referer')
            ->willReturn(['https://badexample.org/endpoint']);

        $domain = $this->fromAllowedDomains($request);

        self::assertNull($domain);
    }
}
