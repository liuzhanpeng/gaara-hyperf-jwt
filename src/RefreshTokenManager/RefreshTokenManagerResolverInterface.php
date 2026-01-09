<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenManager;

/**
 * Refresh Token 管理器解析器接口
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
interface RefreshTokenManagerResolverInterface
{
    /**
     * @param string $name
     * @return RefreshTokenManagerInterface
     */
    public function resolve(string $name = 'default'): RefreshTokenManagerInterface;
}
