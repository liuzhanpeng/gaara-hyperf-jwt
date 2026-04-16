<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\JWTokenManager\JWTokenResponder;

use GaaraHyperf\Config\CustomConfig;
use Hyperf\Contract\ContainerInterface;
use InvalidArgumentException;

class JWTokenResponderFactory
{
    public function __construct(
        private ContainerInterface $container
    ) {
    }

    public function create(array $config): JWTokenResponderInterface
    {
        $type = $config['type'] ?? 'body';
        unset($config['type']);

        switch ($type) {
            case 'cookie':
                return $this->container->make(CookieJWTokenResponder::class, [
                    'cookieName' => $config['cookie_name'] ?? 'access_token',
                    'cookiePath' => $config['cookie_path'] ?? '/',
                    'cookieDomain' => $config['cookie_domain'] ?? '',
                    'cookieSecure' => $config['cookie_secure'] ?? true,
                    'cookieHttpOnly' => $config['cookie_http_only'] ?? true,
                    'cookieSameSite' => $config['cookie_same_site'] ?? 'lax',
                    'template' => $config['template'] ?? null,
                ]);
            case 'body':
                return $this->container->make(BodyJWTokenResponder::class, [
                    'template' => $config['template'] ?? null,
                ]);
            case 'custom':
                $customConfig = CustomConfig::from($config);

                $customResponder = $this->container->make($customConfig->class(), $customConfig->params());
                if (! $customResponder instanceof JWTokenResponderInterface) {
                    throw new InvalidArgumentException(sprintf('The custom JWTokenResponder must implement %s.', JWTokenResponderInterface::class));
                }

                return $customResponder;
            default:
                throw new InvalidArgumentException("JWToken Responder type does not exist: {$type}");
        }
    }
}
