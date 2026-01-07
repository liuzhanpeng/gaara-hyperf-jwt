<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\TokenManager;

use GaaraHyperf\Config\CustomConfig;
use Hyperf\Contract\ContainerInterface;

/**
 * Token管理创建工厂
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class TokenManagerFactory
{
    public function __construct(
        private ContainerInterface $container,
    ) {}

    /**
     * @param array $config
     * @return TokenManagerInterface
     */
    public function create(array $config): TokenManagerInterface
    {
        $type = $config['type'] ?? 'default';
        unset($config['type']);

        switch ($type) {
            case 'default':
                if (!isset($config['secret_key']) || empty($config['secret_key'])) {
                    throw new \InvalidArgumentException('Missing secret key');
                }

                $options = array_merge([
                    'algo' => 'SHA256',
                    'ttl' => 3600,
                    'iss' => 'gaara'
                ], $config);

                return $this->container->make(TokenManager::class, ['options' => $options]);
            case 'custom':
                $customConfig = CustomConfig::from($config);

                $tokenManager = $this->container->make($customConfig->class(), $customConfig->params());
                if (!$tokenManager instanceof TokenManagerInterface) {
                    throw new \LogicException(sprintf('The custom TokenManager must implement %s.', TokenManagerInterface::class));
                }

                return $tokenManager;
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported token manager type: %s', $type));
        }
    }
}
