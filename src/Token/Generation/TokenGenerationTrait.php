<?php

declare(strict_types=1);

namespace T0mmy742\ApiAuthentication\Token\Generation;

use Exception;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\ApiAuthentication\Token\TokenCookieTrait;

use function bin2hex;
use function random_bytes;

trait TokenGenerationTrait
{
    use TokenCookieTrait;

    /**
     * Create a token based on {@link random_bytes()}.
     *
     * @return string a newly generated token.
     * @throws Exception if an appropriate source of randomness cannot be found.
     */
    private function createToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Define Set-Cookie to response header if necessary.
     *
     * @param ServerRequestInterface $request the server request.
     * @param ResponseInterface $response the response.
     * @param string $token the generated token.
     * @return ResponseInterface the response with cookie header if needed.
     *
     * @uses TokenCookieTrait::fromAllowedDomains()
     * @uses TokenCookieTrait::add30MinCookieToResponse()
     */
    private function manageCookieResponse(
        ServerRequestInterface $request,
        ResponseInterface $response,
        string $token
    ): ResponseInterface {
        $domain = $this->fromAllowedDomains($request);

        if ($domain !== null) {
            $response = $this->add30MinCookieToResponse($response, $token, $domain);
        }

        return $response;
    }
}
