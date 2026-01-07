<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticatorBuilderInterface;
use GaaraHyperf\UserProvider\UserProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;
use GaaraHyperf\Authenticator\AuthenticatorInterface;

/**
 * JWT认证器构建器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWTAuthenticatorBuilder implements AuthenticatorBuilderInterface
{
    public function create(array $options, UserProviderInterface $userProvider, EventDispatcher $eventDispatcher): AuthenticatorInterface
    {
        throw new \Exception('Not implemented');
    }
}
