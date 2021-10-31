<?php

declare(strict_types=1);

namespace T0mmy742\ApiAuthentication\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use T0mmy742\ApiAuthentication\Exceptions\AuthException;
use T0mmy742\ApiAuthentication\Token\TokenCookieTrait;
use T0mmy742\ApiAuthentication\Token\Validation\TokenValidationInterface;

use function str_starts_with;
use function strlen;
use function substr;

class AuthMiddleware implements MiddlewareInterface
{
    use TokenCookieTrait;

    private TokenValidationInterface $tokenValidation;
    /** @var string[] */
    private array $cookieDomains;

    /**
     * @param TokenValidationInterface $tokenValidation
     * @param string[] $cookieDomains
     */
    public function __construct(TokenValidationInterface $tokenValidation, array $cookieDomains = [])
    {
        $this->tokenValidation = $tokenValidation;
        $this->cookieDomains = $cookieDomains;
    }

    /**
     * Process the token validation. It retrieves token from either a cookie or the Authorization header,
     * then validates it. If token is invalid or not present, AuthException is thrown.
     *
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws AuthException if token is not present or invalid.
     *
     * @uses TokenCookieTrait::fromAllowedDomains()
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $domain = $this->fromAllowedDomains($request);
        if ($domain !== null) {
            $token = $this->retrieveTokenFromCookie($request);
            $request = $this->tokenValidation->validateToken($token, $request);

            return $this->add30MinCookieToResponse($handler->handle($request), $token, $domain);
        } else {
            $token = $this->retrieveTokenFromHeader($request);
            $request = $this->tokenValidation->validateToken($token, $request);

            return $handler->handle($request);
        }
    }

    /**
     * Retrieve token from a cookie. Throws AuthException if no token cookie is present.
     *
     * @param ServerRequestInterface $request
     * @return string the token present in cookie.
     * @throws AuthException if token is not present.
     */
    private function retrieveTokenFromCookie(ServerRequestInterface $request): string
    {
        $token = $request->getCookieParams()['access_token'] ?? null;
        if ($token === null) {
            throw new AuthException('No token found on request');
        }

        return $token;
    }

    /**
     * Retrieve token from the Authorization header. Throws AuthException if no token present or invalid.
     *
     * @param ServerRequestInterface $request
     * @return string the token present in Authorization header.
     * @throws AuthException if token is not present or invalid.
     */
    private function retrieveTokenFromHeader(ServerRequestInterface $request): string
    {
        $authorizationHeader = $request->getHeader('Authorization')[0] ?? null;
        if ($authorizationHeader === null) {
            throw new AuthException('No token found on request');
        }
        if (!str_starts_with($authorizationHeader, 'Bearer ')) {
            throw new AuthException('No Bearer token found on Authorization header');
        }
        $token = substr($authorizationHeader, 7);
        if (strlen($token) !== 64) {
            throw new AuthException('Bad Bearer token found on Authorization header');
        }

        return $token;
    }
}
