<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenManager;

use GaaraHyperf\JWT\RefreshToken;
use GaaraHyperf\Token\TokenInterface;

/**
 * Refresh Token 管理器接口.
 */
interface RefreshTokenManagerInterface
{
    /**
     * 发布.
     */
    public function issue(TokenInterface $token): RefreshToken;

    /**
     * 解析.
     */
    public function resolve(string $refreshToken): ?TokenInterface;

    /**
     * 撤消.
     */
    public function revoke(string $refreshToken): void;
}
