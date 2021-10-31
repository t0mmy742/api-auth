<?php

declare(strict_types=1);

namespace T0mmy742\ApiAuthentication\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use T0mmy742\ApiAuthentication\Exceptions\AuthException;
use T0mmy742\ApiAuthentication\Middleware\AuthMiddleware;
use T0mmy742\ApiAuthentication\Token\Validation\TokenValidationInterface;

/**
 * @covers \T0mmy742\ApiAuthentication\Middleware\AuthMiddleware
 */
class AuthMiddlewareTest extends TestCase
{
    public function testFromAllowedDomainsNoCookie(): void
    {
        $cookieDomain = 'example.org';

        $tokenValidation = $this->createStub(TokenValidationInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::once())
            ->method('hasHeader')
            ->willReturn(true);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->willReturn(['https://' . $cookieDomain]);
        $request
            ->expects(self::once())
            ->method('getCookieParams')
            ->willReturn([]);

        $handler = $this->createStub(RequestHandlerInterface::class);

        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('No token found on request');
        (new AuthMiddleware($tokenValidation, [$cookieDomain]))->process($request, $handler);
    }

    public function testFromAllowedDomainsCookieInvalidToken(): void
    {
        $cookieDomain = 'example.org';
        $token = '8ba28a85ec598409d31ffc5e21117d0973f83040fac7599fbfd2db8edab84705';

        $tokenValidation = $this->createMock(TokenValidationInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::once())
            ->method('hasHeader')
            ->willReturn(true);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->willReturn(['https://' . $cookieDomain]);
        $request
            ->expects(self::once())
            ->method('getCookieParams')
            ->willReturn(['access_token' => $token]);

        $tokenValidation
            ->expects(self::once())
            ->method('validateToken')
            ->with($token, $request)
            ->willThrowException(new AuthException());

        $handler = $this->createStub(RequestHandlerInterface::class);

        $this->expectException(AuthException::class);
        (new AuthMiddleware($tokenValidation, [$cookieDomain]))->process($request, $handler);
    }

    public function testFromAllowedDomainsCookieValidToken(): void
    {
        $cookieDomain = 'example.org';
        $token = '8ba28a85ec598409d31ffc5e21117d0973f83040fac7599fbfd2db8edab84705';

        $tokenValidation = $this->createMock(TokenValidationInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::once())
            ->method('hasHeader')
            ->willReturn(true);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->willReturn(['https://' . $cookieDomain]);
        $request
            ->expects(self::once())
            ->method('getCookieParams')
            ->willReturn(['access_token' => $token]);

        $tokenValidation
            ->expects(self::once())
            ->method('validateToken')
            ->with($token, $request)
            ->willReturn($request);

        $response = $this->createMock(ResponseInterface::class);
        $response
            ->expects(self::once())
            ->method('withAddedHeader')
            ->with('Set-Cookie', self::isType('string'))
            ->willReturnSelf();

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler
            ->expects(self::once())
            ->method('handle')
            ->with($request)
            ->willReturn($response);

        (new AuthMiddleware($tokenValidation, [$cookieDomain]))->process($request, $handler);
    }

    public function testNotFromAllowedDomainsCookieNoTokenHeader(): void
    {
        $cookieDomain = 'example.org';

        $tokenValidation = $this->createStub(TokenValidationInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::exactly(2))
            ->method('hasHeader')
            ->willReturn(false);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn([]);

        $handler = $this->createStub(RequestHandlerInterface::class);

        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('No token found on request');
        (new AuthMiddleware($tokenValidation, [$cookieDomain]))->process($request, $handler);
    }

    public function testNotFromAllowedDomainsCookieNotABearerTokenHeader(): void
    {
        $cookieDomain = 'example.org';
        $token = '8ba28a85ec598409d31ffc5e21117d0973f83040fac7599fbfd2db8edab84705';

        $tokenValidation = $this->createStub(TokenValidationInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::exactly(2))
            ->method('hasHeader')
            ->willReturn(false);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn(['NOTBEARER ' . $token]);

        $handler = $this->createStub(RequestHandlerInterface::class);

        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('No Bearer token found on Authorization header');
        (new AuthMiddleware($tokenValidation, [$cookieDomain]))->process($request, $handler);
    }

    public function testNotFromAllowedDomainsCookieBearerTokenHeaderBadLength(): void
    {
        $cookieDomain = 'example.org';
        $token = 'BAD-TOKEN-INVALID-LENGTH';

        $tokenValidation = $this->createStub(TokenValidationInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::exactly(2))
            ->method('hasHeader')
            ->willReturn(false);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn(['Bearer ' . $token]);

        $handler = $this->createStub(RequestHandlerInterface::class);

        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('Bad Bearer token found on Authorization header');
        (new AuthMiddleware($tokenValidation, [$cookieDomain]))->process($request, $handler);
    }

    public function testNotFromAllowedDomainsCookieBearerTokenHeaderInvalid(): void
    {
        $cookieDomain = 'example.org';
        $token = '8ba28a85ec598409d31ffc5e21117d0973f83040fac7599fbfd2db8edab84705';

        $tokenValidation = $this->createMock(TokenValidationInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::exactly(2))
            ->method('hasHeader')
            ->willReturn(false);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn(['Bearer ' . $token]);

        $tokenValidation
            ->expects(self::once())
            ->method('validateToken')
            ->with($token, $request)
            ->willThrowException(new AuthException());

        $handler = $this->createStub(RequestHandlerInterface::class);

        $this->expectException(AuthException::class);
        (new AuthMiddleware($tokenValidation, [$cookieDomain]))->process($request, $handler);
    }

    public function testNotFromAllowedDomainsCookieBearerTokenHeaderValid(): void
    {
        $cookieDomain = 'example.org';
        $token = '8ba28a85ec598409d31ffc5e21117d0973f83040fac7599fbfd2db8edab84705';

        $tokenValidation = $this->createMock(TokenValidationInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->expects(self::exactly(2))
            ->method('hasHeader')
            ->willReturn(false);
        $request
            ->expects(self::once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn(['Bearer ' . $token]);

        $tokenValidation
            ->expects(self::once())
            ->method('validateToken')
            ->with($token, $request)
            ->willReturn($request);

        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler
            ->expects(self::once())
            ->method('handle')
            ->with($request)
            ->willReturn($response);

        (new AuthMiddleware($tokenValidation, [$cookieDomain]))->process($request, $handler);
    }
}
