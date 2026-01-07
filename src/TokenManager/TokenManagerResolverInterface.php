<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\TokenManager;

/**
 * Token管理器的解析器接口
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
interface TokenManagerResolverInterface
{
    /**
     * @param string $name
     * @return TokenManagerInterface
     */
    public function resolve(string $name = 'default'): TokenManagerInterface;
}
