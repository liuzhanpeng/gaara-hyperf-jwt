<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenManager;

use GaaraHyperf\JWT\RefreshToken;
use GaaraHyperf\Token\TokenInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * 内置的Refresh Token 管理器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class RefreshTokenManager implements RefreshTokenManagerInterface
{
    /**
     * @param CacheInterface $cache
     * @param string $prefix
     * @param integer $expiresIn
     * @param integer $refreshTokenLength
     */
    public function __construct(
        private CacheInterface $cache,
        private string $prefix,
        private int $expiresIn,
        private int $refreshTokenLength,
    ) {}

    /**
     * @inheritDoc
     */
    public function issue(TokenInterface $token): RefreshToken
    {
        $refreshToken = bin2hex(random_bytes($this->refreshTokenLength));

        $this->cache->set($this->getCacheKey($refreshToken), $token, $this->expiresIn);

        return new RefreshToken($refreshToken, $this->expiresIn);
    }

    /**
     * @inheritDoc
     */
    public function resolve(string $refreshToken): ?TokenInterface
    {
        $cacheKey = $this->getCacheKey($refreshToken);
        $token = $this->cache->get($cacheKey);
        if (is_null($token)) {
            return null;
        }

        return $token;
    }

    /**
     * @inheritDoc
     */
    public function revoke(string $refreshToken): void
    {
        $this->cache->delete($this->getCacheKey($refreshToken));
    }

    /**
     * 返回缓存key
     *
     * @param string $refreshToken
     * @return string
     */
    private function getCacheKey(string $refreshToken): string
    {
        return sprintf('%s%s', $this->prefix, $refreshToken);
    }
}
