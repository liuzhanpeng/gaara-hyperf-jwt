<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\JWTokenManager;

use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\Token\TokenInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * 令牌管理器接口.
 */
interface JWTokenManagerInterface
{
    /**
     * 发布令牌.
     */
    public function issue(TokenInterface $token, array $customClaims = []): ResponseInterface;

    /**
     * 解析访问令牌, 失败时抛出异常.
     */
    public function resolveAccessToken(ServerRequestInterface $request): ?JWTUser;

    /**
     * 是否启用刷新令牌机制.
     */
    public function isRefreshTokenEnabled(): bool;

    /**
     * 刷新令牌的请求路径.
     */
    public function refreshTokenPath(): string;

    /**
     * 解析刷新令牌, 失败时返回null.
     */
    public function resolveRefreshToken(ServerRequestInterface $request): ?TokenInterface;

    /**
     * 撤消刷新令牌.
     */
    public function revokeRefreshToken(ServerRequestInterface $request): void;
}
