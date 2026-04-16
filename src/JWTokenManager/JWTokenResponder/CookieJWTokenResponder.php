<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\JWTokenManager\JWTokenResponder;

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\RefreshToken;
use Hyperf\HttpMessage\Cookie\Cookie;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;

class CookieJWTokenResponder implements JWTokenResponderInterface
{
    public function __construct(
        private \Hyperf\HttpServer\Contract\ResponseInterface $response,
        private string $cookieName = 'refresh_token',
        private string $cookiePath = '/',
        private string $cookieDomain = '',
        private bool $cookieSecure = true,
        private bool $cookieHttpOnly = true,
        private string $cookieSameSite = 'lax',
        private ?string $template = null,
    ) {
    }

    public function respond(AccessToken $accessToken, ?RefreshToken $refreshToken = null): ResponseInterface
    {
        $response = $this->response;

        if ($refreshToken !== null) {
            $cookie = new Cookie(
                name: $this->cookieName,
                value: $refreshToken->token(),
                expire: time() + $refreshToken->expiresIn(),
                path: $this->cookiePath,
                domain: $this->cookieDomain,
                secure: $this->cookieSecure,
                httpOnly: $this->cookieHttpOnly,
                sameSite: $this->cookieSameSite,
            );

            $response = $this->response->withCookie($cookie);
        }

        return $response->json(json_decode($this->getResponseTemplate($accessToken), true));
    }

    private function getResponseTemplate(AccessToken $accessToken): string
    {
        $template = str_replace(
            ['#ACCESS_TOKEN#', '#EXPIRES_IN#'],
            [$accessToken->token(), $accessToken->expiresIn()],
            $this->template ?? '{"code": 0, "message": "success"}'
        );

        if (! is_string($template) || ! is_array(json_decode($template, true))) {
            throw new InvalidArgumentException('Response template must be a valid JSON string');
        }

        return $template;
    }
}
