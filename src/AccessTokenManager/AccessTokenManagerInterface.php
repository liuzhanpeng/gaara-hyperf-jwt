<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenManager;

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\Token\TokenInterface;

/**
 * AccessToken管理器接口.
 */
interface AccessTokenManagerInterface
{
    /**
     * 发布.
     */
    public function issue(TokenInterface $token, array $customClaims = []): AccessToken;

    /**
     * 解析, 失败时抛出异常.
     */
    public function parse(string $accessToken): JWTUser;
}
