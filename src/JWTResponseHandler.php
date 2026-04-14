<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticationSuccessHandlerInterface;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolverInterface;
use GaaraHyperf\Passport\Passport;
use GaaraHyperf\Token\TokenInterface;
use Hyperf\HttpMessage\Cookie\Cookie;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * JWT响应处理器.
 */
class JWTResponseHandler implements AuthenticationSuccessHandlerInterface
{
    public function __construct(
        private AccessTokenManagerResolverInterface $accessTokenManagerResolver,
        private RefreshTokenManagerResolverInterface $refreshTokenManagerResolver,
        private \Hyperf\HttpServer\Contract\ResponseInterface $response,
        private string $accessTokenManager = 'default',
        private string $refreshTokenManager = 'default',
        private string $refreshTokenResponseType = 'body',
        private ?string $responseTemplate = null,
        private string $refreshTokenCookieName = 'refresh_token',
        private string $refreshTokenCookiePath = '/',
        private string $refreshTokenCookieDomain = '',
        private bool $refreshTokenCookieSecure = true,
        private bool $refreshTokenCookieHttpOnly = true,
        private string $refreshTokenCookieSameSite = 'lax',
        private bool $refreshTokenEnabled = true,
    ) {
    }

    public function handle(string $guardName, ServerRequestInterface $request, TokenInterface $token, Passport $passport): ?ResponseInterface
    {
        $user = $passport->getUser();
        $customClaims = $user instanceof JWTCustomClaimAwareUserInterface ? $user->getJWTCustomClaims() : [];

        $accessToken = $this->accessTokenManagerResolver->resolve($this->accessTokenManager)->issue($token, $customClaims);

        if (! $this->refreshTokenEnabled) {
            return $this->response->json(json_decode($this->getResponseTemplate($accessToken), true));
        }

        $refreshToken = $this->refreshTokenManagerResolver->resolve($this->refreshTokenManager)->issue($token);

        if ($this->refreshTokenResponseType === 'cookie') {
            $cookie = new Cookie(
                name: $this->refreshTokenCookieName,
                value: $refreshToken->token(),
                expire: time() + $refreshToken->expiresIn(),
                path: $this->refreshTokenCookiePath,
                domain: $this->refreshTokenCookieDomain,
                secure: $this->refreshTokenCookieSecure,
                httpOnly: $this->refreshTokenCookieHttpOnly,
                sameSite: $this->refreshTokenCookieSameSite,
            );

            return $this->response->withCookie($cookie)->json(json_decode($this->getResponseTemplate($accessToken), true));
        }

        return $this->response->json(json_decode($this->getResponseTemplate($accessToken, $refreshToken), true));
    }

    private function getResponseTemplate(AccessToken $accessToken, ?RefreshToken $refreshToken = null): string
    {
        if ($refreshToken !== null) {
            $template = str_replace(
                ['#ACCESS_TOKEN#', '#EXPIRES_IN#', '#REFRESH_TOKEN#'],
                [$accessToken->token(), $accessToken->expiresIn(), $refreshToken->token()],
                $this->responseTemplate ?? '{"access_token": "#ACCESS_TOKEN#", "expires_in": #EXPIRES_IN#, "refresh_token": "#REFRESH_TOKEN#"}'
            );
        } else {
            $template = str_replace(
                ['#ACCESS_TOKEN#', '#EXPIRES_IN#'],
                [$accessToken->token(), $accessToken->expiresIn()],
                $this->responseTemplate ?? '{"access_token": "#ACCESS_TOKEN#", "expires_in": #EXPIRES_IN#}'
            );
        }

        if (! is_string($template) || ! is_array(json_decode($template, true))) {
            throw new InvalidArgumentException('Response template must be a valid JSON string');
        }

        return $template;
    }
}
