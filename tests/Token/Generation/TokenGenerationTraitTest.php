<?php

declare(strict_types=1);

namespace T0mmy742\ApiAuthentication\Tests\Token\Generation;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\ApiAuthentication\Token\Generation\TokenGenerationTrait;

use function strlen;

/**
 * @covers \T0mmy742\ApiAuthentication\Token\Generation\TokenGenerationTrait
 */
class TokenGenerationTraitTest extends TestCase
{
    use TokenGenerationTrait;

    /** @var string[] */
    private array $cookieDomains = ['example.org'];

    public function testCreateToken(): void
    {
        $token = $this->createToken();

        self::assertSame(64, strlen($token));
    }

    /**
     * @uses \T0mmy742\ApiAuthentication\Token\TokenCookieTrait::fromAllowedDomains()
     */
    public function testManageCookieResponseNotAllowedDomain(): void
    {
        $token = '8ba28a85ec598409d31ffc5e21117d0973f83040fac7599fbfd2db8edab84705';

        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->createStub(ResponseInterface::class);

        $request->method('hasHeader')->willReturn(false);

        $newResponse = $this->manageCookieResponse($request, $response, $token);

        self::assertSame($response, $newResponse);
    }

    /**
     * @uses \T0mmy742\ApiAuthentication\Token\TokenCookieTrait::fromAllowedDomains()
     * @uses \T0mmy742\ApiAuthentication\Token\TokenCookieTrait::add30MinCookieToResponse()
     * @uses \T0mmy742\ApiAuthentication\Token\TokenCookieTrait::generate30MinCookie()
     * @uses \T0mmy742\ApiAuthentication\Token\TokenCookieTrait::generateCookie()
     */
    public function testManageCookieResponseAllowedDomain(): void
    {
        $token = '8ba28a85ec598409d31ffc5e21117d0973f83040fac7599fbfd2db8edab84705';

        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->createStub(ResponseInterface::class);
        $response2 = $this->createStub(ResponseInterface::class);

        $request->method('hasHeader')->willReturn(true);
        $request->method('getHeader')->willReturn(['https://example.org/endpoint']);
        $response->method('withAddedHeader')->willReturn($response2);


        $newResponse = $this->manageCookieResponse($request, $response, $token);

        self::assertSame($response2, $newResponse);
    }
}
