<?php

declare(strict_types=1);

namespace T0mmy742\ApiAuthentication\Token\Validation;

use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\ApiAuthentication\Exceptions\AuthException;

trait TokenValidationTrait
{
    /**
     * @see TokenValidationInterface::validateToken()
     */
    public function validateToken(string $token, ServerRequestInterface $request): ServerRequestInterface
    {
        $userId = $this->retrieveUserId($token);

        if ($userId === null) {
            throw new AuthException('Token is not valid');
        }

        return $request->withAttribute('uid', $userId);
    }

    /**
     * Check if received token is valid. It should return user ID corresponding to this token. When null is returned
     * value, it means no user match this token.
     * This function can be used to update a 'last_access' column of the database table of this token.
     *
     * @param string $token
     * @return string|null The user ID corresponding to this token, null if token is invalid.
     */
    abstract private function retrieveUserId(string $token): ?string;
}
