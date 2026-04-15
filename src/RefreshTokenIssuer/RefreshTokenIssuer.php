<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenIssuer;

use GaaraHyperf\JWT\RefreshToken;
use GaaraHyperf\Token\TokenInterface;
use InvalidArgumentException;
use Psr\SimpleCache\CacheInterface;

/**
 * 内置的Refresh Token 发行器.
 */
class RefreshTokenIssuer implements RefreshTokenIssuerInterface
{
    public function __construct(
        private CacheInterface $cache,
        private string $prefix,
        private int $ttl,
        private bool $singleSession,
        private int $refreshTokenLength,
    ) {
        if ($refreshTokenLength < 32) {
            throw new InvalidArgumentException('The refresh token length must be at least 32 characters.');
        }
    }

    public function issue(TokenInterface $token): RefreshToken
    {
        $refreshToken = bin2hex(random_bytes($this->refreshTokenLength / 2));

        if ($this->singleSession) {
            $preRefreshToken = $this->cache->get($this->getUserCacheKey($token->getUserIdentifier()));
            if (! is_null($preRefreshToken)) {
                $this->cache->delete($this->getRefreshTokenCacheKey($preRefreshToken));
            }

            $this->cache->set($this->getUserCacheKey($token->getUserIdentifier()), $refreshToken, $this->ttl);
        }

        $this->cache->set($this->getRefreshTokenCacheKey($refreshToken), $token, $this->ttl);

        return new RefreshToken($refreshToken, $this->ttl);
    }

    public function resolve(string $refreshToken): ?TokenInterface
    {
        $cacheKey = $this->getRefreshTokenCacheKey($refreshToken);
        $token = $this->cache->get($cacheKey);
        if (is_null($token)) {
            return null;
        }

        return $token;
    }

    public function revoke(string $refreshToken): void
    {
        if ($this->singleSession) {
            $token = $this->resolve($refreshToken);
            if (! is_null($token)) {
                $this->cache->delete($this->getUserCacheKey($token->getUserIdentifier()));
            }
        }

        $this->cache->delete($this->getRefreshTokenCacheKey($refreshToken));
    }

    /**
     * 返回缓存key.
     */
    private function getRefreshTokenCacheKey(string $refreshToken): string
    {
        return sprintf('%s:%s', $this->prefix, $refreshToken);
    }

    /**
     * 返回用户Token键.
     */
    private function getUserCacheKey(string $identifier): string
    {
        return sprintf('%s:user:%s', $this->prefix, $identifier);
    }
}
