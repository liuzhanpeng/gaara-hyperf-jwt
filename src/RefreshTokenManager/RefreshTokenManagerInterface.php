<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenManager;

use GaaraHyperf\JWT\RefreshToken;
use GaaraHyperf\Token\TokenInterface;

/**
 * Refresh Token 管理器接口
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
interface RefreshTokenManagerInterface
{
    /**
     * 发布
     *
     * @param TokenInterface $token
     * @return RefreshToken
     */
    public function issue(TokenInterface $token): RefreshToken;

    /**
     * 解析
     *
     * @param string $refreshToken
     * @return TokenInterface|null
     */
    public function resolve(string $refreshToken): ?TokenInterface;

    /**
     * 撤消
     *
     * @param string $refreshToken
     * @return void
     */
    public function revoke(string $refreshToken): void;
}
