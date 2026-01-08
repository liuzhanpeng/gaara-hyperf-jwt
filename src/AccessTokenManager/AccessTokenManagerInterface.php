<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenManager;

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\Exception\JWTException;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\Token\TokenInterface;

/**
 * AccessToken管理器接口
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
interface AccessTokenManagerInterface
{
    /**
     * 发布
     * 
     * @param TokenInterface $token
     * @return AccessToken
     */
    public function issue(TokenInterface $token): AccessToken;

    /**
     * 解析, 失败时抛出异常
     * 
     * @param string $accessToken
     * @return JWTUser
     * @throws JWTException
     */
    public function parse(string $accessToken): JWTUser;
}
