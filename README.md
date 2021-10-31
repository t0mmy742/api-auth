# API Auth
BADGES

API Auth provides an authentication system for API and SPA.
It uses a PSR-15 middleware and parts to generate token for login requests are provided.

## How it works

First, your user get a token from an endpoint of your API (let's say ```/token``` endpoint using POST request).
If this request come from a known domain (for example, your SPA), a cookie is set to client browser with expiration of 30 minutes.
Otherwise, no cookie is set and token is only return by response body as JSON.
Body response is like: ```{"token": "MY-TOKEN"}```.

### Requests with cookie

Cookie token is secured and inaccessible from client.
Each time a request is made to the API, if token is still valid, expiration is set to another 30 minutes.
Session will expire after 30 minutes without request.

### Requests without cookie

If no cookie have been set from your login endpoint, it means it is not an allowed domain (for example, a mobile application).
Token should have been stored to a secure storage.
Each time you make a request, you need to authenticate with Bearer authorization header.  
```Authorization: Bearer MY-TOKEN```  

### No authentication

If a request is made without cookie, without Authorization request, or with a bad token, ```AuthMiddleware``` throw an ```AuthException```.
You should catch this exception to return an appropriate response to your client (and redirect to login page).

## Installation

It is recommended to install this package using [Composer](https://getcomposer.org/)

```shell
composer require t0mmy742/api-auth
```

API Auth requires PHP 8.0 or newer

## Usage

This package is composed of two parts: token creation and token validation.

### Create authentication token

You probably want to authenticate your users using the ```/token``` or ```/login``` endpoint of your API.
Your endpoint can have the following Controller:

```php
<?php

declare(strict_types=1);

namespace YOUR\NAMESPACE\Controller;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\ApiAuthentication\Token\Generation\TokenGenerationTrait;

use function is_array;
use function json_encode;

class TokenController
{
    use TokenGenerationTrait;

    /** @var string[] */
    private array $cookieDomains = ['example.org'];

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $params = $request->getParsedBody();

        if (is_array($params)) {
            $login = $params['login'] ?? null;
            $pass = $params['pass'] ?? null;

            if ($login !== null && $pass !== null) {
                if ($this->validAuth($login, $pass)) {
                    // Create a new token
                    $token = $this->createToken();
                    // Add token to a cookie if origin domain is allowed ($this->cookieDomains). Can be from a SPA
                    $response = $this->manageCookieResponse($request, $response, $token);
                }
            }
        }

        // Write token to the response body
        $response->getBody()->write(json_encode(['token' => $token]));
        
        return $response;
    }

    private function validAuth(string $login, string $pass): bool
    {
        // You probably want to check in database...
        return true;
    }
}

```

### Validate authentication token

To validate token, you need to add ```AuthMiddleware``` class to your middleware stack.
This middleware has the following signature:
```php
public function __construct(\T0mmy742\ApiAuthentication\Token\Validation\TokenValidationInterface $tokenValidation, array $cookieDomains = []);
```
```$cookieDomains``` is an array containing allowed domains to set a cookie named ```access_token``` with the authentication token.
It is useful to authenticate a user from your SPA.
Mobile application does not have domain, and use Bearer token authentication.  
For example, if your API host is ```api.example.org```, your SPA is probably ```example.org```. Then, we have ```$cookieDomains = ['example.org']```.

```$tokenValidation``` is a class implementing ```TokenValidationInterface```.
Implementation can be as bellow:
```php
<?php

declare(strict_types=1);

namespace YOUR\NAMESPACE\Auth;

use T0mmy742\ApiAuthentication\Token\Validation\TokenValidationTrait;

class TokenValidation implements \T0mmy742\ApiAuthentication\Token\Validation\TokenValidationInterface
{
    use TokenValidationTrait;

    private function retrieveUserId(string $token): ?string
    {
        // You probably want to make request to your database to get userId from this token
        // Return userId if exists, return null otherwise.
        return '1'
    }
}

```

## License

API Auth is licensed under the [MIT license](LICENSE.md).