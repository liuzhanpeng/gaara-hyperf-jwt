<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenIssuer;

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\Token\TokenInterface;

/**
 * AccessToken发行器接口.
 */
interface AccessTokenIssuerInterface
{
    /**
     * 发布.
     */
    public function issue(TokenInterface $token, array $customClaims = []): AccessToken;

    /**
     * 解析, 失败时抛出异常.
     */
    public function resolve(string $accessToken): JWTUser;
}
