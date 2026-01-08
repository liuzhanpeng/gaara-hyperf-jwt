<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenManager;

/**
 * AccessToken管理器的解析器接口
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
interface AccessTokenManagerResolverInterface
{
    /**
     * @param string $name
     * @return AccessTokenManagerInterface
     */
    public function resolve(string $name = 'default'): AccessTokenManagerInterface;
}
