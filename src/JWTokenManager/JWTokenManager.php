<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\JWTokenManager;

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorInterface;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\JWTokenResponderInterface;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerInterface;
use GaaraHyperf\Token\TokenInterface;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class JWTokenManager implements JWTokenManagerInterface
{
    public function __construct(
        private AccessTokenExtractorInterface $accessTokenExtractor,
        private AccessTokenIssuerInterface $accessTokenIssuer,
        private JWTokenResponderInterface $responder,
        private bool $isRefreshTokenEnabled = true,
        private string $refreshTokenPath = '',
        private string $logoutPath = '',
        private ?AccessTokenExtractorInterface $refreshTokenExtractor = null,
        private ?RefreshTokenIssuerInterface $refreshTokenIssuer = null,
    ) {
        if ($this->isRefreshTokenEnabled) {
            if ($this->refreshTokenPath === '') {
                throw new InvalidArgumentException('Refresh path must be provided when refresh token is enabled.');
            }
            if ($this->logoutPath === '') {
                throw new InvalidArgumentException('Logout path must be provided when refresh token is enabled.');
            }
            if ($this->refreshTokenExtractor === null) {
                throw new InvalidArgumentException('Refresh token extractor must be provided when refresh token is enabled.');
            }
            if ($this->refreshTokenIssuer === null) {
                throw new InvalidArgumentException('Refresh token issuer must be provided when refresh token is enabled.');
            }
        }
    }

    public function issue(TokenInterface $token, array $customClaims = []): ResponseInterface
    {
        $accessToken = $this->accessTokenIssuer->issue($token, $customClaims);
        $refreshToken = null;
        if ($this->isRefreshTokenEnabled) {
            $refreshToken = $this->refreshTokenIssuer->issue($token);
        }

        return $this->responder->respond($accessToken, $refreshToken);
    }

    public function resolveAccessToken(ServerRequestInterface $request): ?JWTUser
    {
        $accessToken = $this->accessTokenExtractor->extract($request);
        if ($accessToken === null) {
            return null;
        }

        return $this->accessTokenIssuer->resolve($accessToken);
    }

    public function isRefreshTokenEnabled(): bool
    {
        return $this->isRefreshTokenEnabled;
    }

    public function refreshTokenPath(): string
    {
        return $this->refreshTokenPath;
    }

    public function logoutPath(): string
    {
        return $this->logoutPath;
    }

    public function resolveRefreshToken(ServerRequestInterface $request): ?TokenInterface
    {
        if (! $this->isRefreshTokenEnabled) {
            return null;
        }

        $refreshToken = $this->refreshTokenExtractor->extract($request);
        if ($refreshToken === null) {
            return null;
        }

        return $this->refreshTokenIssuer->resolve($refreshToken);
    }

    public function revokeRefreshToken(ServerRequestInterface $request): void
    {
        if (! $this->isRefreshTokenEnabled) {
            return;
        }

        $refreshToken = $this->refreshTokenExtractor->extract($request);
        if ($refreshToken === null) {
            return;
        }

        $this->refreshTokenIssuer->revoke($refreshToken);
    }
}
