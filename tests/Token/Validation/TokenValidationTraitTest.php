<?php

declare(strict_types=1);

namespace T0mmy742\ApiAuthentication\Tests\Token\Validation;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\ApiAuthentication\Exceptions\AuthException;

/**
 * @covers \T0mmy742\ApiAuthentication\Token\Validation\TokenValidationTrait
 */
class TokenValidationTraitTest extends TestCase
{
    public function testValidateTokenInvalid(): void
    {
        $token = '8ba28a85ec598409d31ffc5e21117d0973f83040fac7599fbfd2db8edab84705';

        $traitClass = new TokenValidationHelper(false);

        $request = $this->createStub(ServerRequestInterface::class);

        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('Token is not valid');
        $traitClass->validateToken($token, $request);
    }

    public function testValidateTokenValid(): void
    {
        $token = '8ba28a85ec598409d31ffc5e21117d0973f83040fac7599fbfd2db8edab84705';

        $traitClass = new TokenValidationHelper(true);

        $request = $this->createMock(ServerRequestInterface::class);
        $request2 = $this->createStub(ServerRequestInterface::class);
        $request
            ->expects(self::once())
            ->method('withAttribute')
            ->with('uid', '1')
            ->willReturn($request2);

        $newRequest = $traitClass->validateToken($token, $request);

        self::assertSame($request2, $newRequest);
    }
}
