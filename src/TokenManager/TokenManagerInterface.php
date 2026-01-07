<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\TokenManager;

use GaaraHyperf\Token\TokenInterface;

/**
 * Token管理器接口
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
interface TokenManagerInterface
{
    /**
     * 发布令牌
     * 
     * @param TokenInterface $token
     * @return string
     */
    public function issue(TokenInterface $token): string;

    /**
     * 解析令牌
     * 
     * @param string $accessToken
     * @return JWTokenInterface
     */
    public function resolve(string $accessToken): JWTokenInterface;

    /**
     * 撤消令牌
     *
     * @param string $accessToken
     * @return void
     */
    public function revoke(string $accessToken): void;
}
