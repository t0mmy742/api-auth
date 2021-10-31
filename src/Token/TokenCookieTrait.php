<?php

declare(strict_types=1);

namespace T0mmy742\ApiAuthentication\Token;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function in_array;
use function is_string;
use function parse_url;

use const PHP_URL_HOST;

trait TokenCookieTrait
{
    /**
     * Add a cookie value expiring in 30 minutes from now to the response.
     *
     * @param ResponseInterface $response
     * @param string $token
     * @param string $domain
     * @return ResponseInterface
     *
     * @uses TokenCookieTrait::generate30MinCookie()
     */
    private function add30MinCookieToResponse(
        ResponseInterface $response,
        string $token,
        string $domain
    ): ResponseInterface {
        return $response->withAddedHeader(
            'Set-Cookie',
            $this->generate30MinCookie($token, $domain)
        );
    }

    /**
     * Generate a cookie value expiring in 30 minutes from now.
     *
     * @param string $token
     * @param string $domain
     * @return string
     *
     * @uses TokenCookieTrait::generateCookie()
     */
    private function generate30MinCookie(string $token, string $domain): string
    {
        return $this->generateCookie('access_token', $token, gmdate('D, d-M-Y H:i:s e', time() + 30 * 60), $domain);
    }

    /**
     * Generate a cookie value of Set-Cookie header based on parameters.
     *
     * @param string $cookieName
     * @param string $token
     * @param string $expires
     * @param string $domain
     * @return string
     */
    private function generateCookie(string $cookieName, string $token, string $expires, string $domain): string
    {
        return $cookieName . '=' . $token
            . '; Expires=' . $expires
            . '; Domain=' . $domain
            . '; Path=' . '/'
            . '; Secure'
            . '; HttpOnly'
            . '; SameSite=Strict';
    }

    /**
     * Check if domain of the current request is part of $this->cookieDomains.
     *
     * @param ServerRequestInterface $request
     * @return string|null
     */
    private function fromAllowedDomains(ServerRequestInterface $request): ?string
    {
        if ($request->hasHeader('Referer')) {
            $uriHeader = $request->getHeader('Referer')[0];
        } elseif ($request->hasHeader('Origin')) {
            $uriHeader = $request->getHeader('Origin')[0];
        } else {
            return null;
        }

        $domain = parse_url($uriHeader, PHP_URL_HOST);

        if (!is_string($domain)) {
            return null;
        }

        return in_array($domain, $this->cookieDomains, true) ? $domain : null;
    }
}
