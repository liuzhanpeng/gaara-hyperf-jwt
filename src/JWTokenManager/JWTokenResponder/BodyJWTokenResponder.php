<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\JWTokenManager\JWTokenResponder;

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\RefreshToken;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;

class BodyJWTokenResponder implements JWTokenResponderInterface
{
    public function __construct(
        private \Hyperf\HttpServer\Contract\ResponseInterface $response,
        private ?string $template = null
    ) {
    }

    public function respond(AccessToken $accessToken, ?RefreshToken $refreshToken = null): ResponseInterface
    {
        return $this->response->json(json_decode($this->getResponseTemplate($accessToken, $refreshToken), true));
    }

    private function getResponseTemplate(AccessToken $accessToken, ?RefreshToken $refreshToken = null): string
    {
        if ($refreshToken !== null) {
            $template = str_replace(
                ['#ACCESS_TOKEN#', '#EXPIRES_IN#', '#REFRESH_TOKEN#', '#REFRESH_EXPIRES_IN#'],
                [$accessToken->token(), $accessToken->expiresIn(), $refreshToken->token(), $refreshToken->expiresIn()],
                $this->template ?? '{"code": 0, "message": "success", "data": {"access_token": "#ACCESS_TOKEN#", "expires_in": #EXPIRES_IN#, "refresh_token": "#REFRESH_TOKEN#", "refresh_expires_in": #REFRESH_EXPIRES_IN#}}'
            );
        } else {
            $template = str_replace(
                ['#ACCESS_TOKEN#', '#EXPIRES_IN#'],
                [$accessToken->token(), $accessToken->expiresIn()],
                $this->template ?? '{"code": 0, "message": "success", "data": {"access_token": "#ACCESS_TOKEN#", "expires_in": #EXPIRES_IN#}}'
            );
        }

        if (! is_string($template) || ! is_array(json_decode($template, true))) {
            throw new InvalidArgumentException('Response template must be a valid JSON string');
        }

        return $template;
    }
}
