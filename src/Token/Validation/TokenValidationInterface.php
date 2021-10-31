<?php

declare(strict_types=1);

namespace T0mmy742\ApiAuthentication\Token\Validation;

use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\ApiAuthentication\Exceptions\AuthException;

interface TokenValidationInterface
{
    /**
     * Check if received token is valid. It should return a new ServerRequestInterface with an attribute having the
     * user ID corresponding to this token. If no user match this token, AuthException thrown.
     *
     * @param string $token the token to validate.
     * @param ServerRequestInterface $request the server request from where come the token.
     * @return ServerRequestInterface A new server request with the user ID corresponding to this token as an attribute,
     * null if token is invalid.
     * @throws AuthException if no user match the token
     */
    public function validateToken(string $token, ServerRequestInterface $request): ServerRequestInterface;
}
