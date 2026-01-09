<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticationSuccessHandlerInterface;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolverInterface;
use Psr\Http\Message\ServerRequestInterface;
use GaaraHyperf\Token\TokenInterface;
use GaaraHyperf\Passport\Passport;
use Psr\Http\Message\ResponseInterface;

/**
 * JWT响应处理器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWTResponseHandler implements AuthenticationSuccessHandlerInterface
{
    public function __construct(
        private AccessTokenManagerResolverInterface $accessTokenManagerResolver,
        private RefreshTokenManagerResolverInterface $refreshTokenManagerResolver,
        private \Hyperf\HttpServer\Contract\ResponseInterface $response,
        private string $accessTokenManager = 'default',
        private string $refreshTokenManager = 'default',
        private ?string $refreshTokenResponseType = null,
        private ?string $responseTemplate = null,
        private ?string $refreshTokenCookieName = null,
        private ?string $refreshTokenCookiePath = null,
        private ?string $refreshTokenCookieDomain = null,
        private ?bool $refreshTokenCookieSecure = null,
        private ?string $refreshTokenCookieSameSite = null,
    ) {}

    public function handle(string $guardName, ServerRequestInterface $request, TokenInterface $token, Passport $passport): ?ResponseInterface
    {
        $accessToken = $this->accessTokenManagerResolver->resolve($this->accessTokenManager)->issue($token);
        $refreshToken = $this->refreshTokenManagerResolver->resolve($this->refreshTokenManager)->issue($token);

        if ($this->refreshTokenResponseType === 'cookie') {
            $cookie = new \Hyperf\HttpMessage\Cookie\Cookie(
                name: $this->refreshTokenCookieName ?? 'refresh_token',
                value: $refreshToken->token(),
                expire: time() + $refreshToken->expiresIn(),
                path: $this->refreshTokenCookiePath ?? '/',
                domain: $this->refreshTokenCookieDomain,
                secure: $this->refreshTokenCookieSecure ?? true,
                sameSite: $this->refreshTokenCookieSameSite ?? 'lax',
            );

            return $this->response->withCookie($cookie)->json([
                'access_token' => $accessToken->token(),
                'expires_in' => $accessToken->expiresIn(),
            ]);
        }

        $template = str_replace(
            ['#ACCESS_TOKEN#', '#EXPIRES_IN#', "#REFRESH_TOKEN#"],
            [$accessToken->token(), $accessToken->expiresIn(), $refreshToken->token()],
            $this->responseTemplate ?? '{"access_token": "#ACCESS_TOKEN#", "expires_in": #EXPIRES_IN#, "refresh_token": "#REFRESH_TOKEN#"}'
        );

        if (!is_string($template) || !is_array(json_decode($template, true))) {
            throw new \InvalidArgumentException('Response template must be a valid JSON string');
        }

        return $this->response->json(json_decode($template, true));
    }
}
