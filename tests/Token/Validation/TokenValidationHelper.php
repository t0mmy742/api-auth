<?php

declare(strict_types=1);

namespace T0mmy742\ApiAuthentication\Tests\Token\Validation;

use T0mmy742\ApiAuthentication\Token\Validation\TokenValidationTrait;

class TokenValidationHelper// implements \T0mmy742\ApiAuthentication\Token\Validation\TokenValidationInterface
{
    use TokenValidationTrait;

    private bool $tokenValid;

    public function __construct(bool $tokenValid)
    {
        $this->tokenValid = $tokenValid;
    }

    private function retrieveUserId(string $token): ?string
    {
        if ($this->tokenValid) {
            return '1';
        } else {
            return null;
        }
    }
}
