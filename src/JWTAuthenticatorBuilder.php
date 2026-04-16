<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticatorInterface;
use GaaraHyperf\Authenticator\Builder\AbstractAuthenticatorBuilder;
use GaaraHyperf\JWT\EventListener\JWTRevokeLogoutListener;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerResolverInterface;
use GaaraHyperf\UserProvider\UserProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * JWT认证器构建器.
 */
class JWTAuthenticatorBuilder extends AbstractAuthenticatorBuilder
{
    public function create(array $options, UserProviderInterface $userProvider, EventDispatcher $eventDispatcher): AuthenticatorInterface
    {
        $options = $options + [
            'jwt_manager' => 'default',
        ];

        $jwtManager = $this->container->get(JWTokenManagerResolverInterface::class)->resolve($options['jwt_manager']);

        $eventDispatcher->addSubscriber(new JWTRevokeLogoutListener($jwtManager));

        return new JWTAuthenticator(
            jwTokenManager: $jwtManager,
            userProvider: $userProvider,
            eventDispatcher: $eventDispatcher,
            successHandler: $this->createSuccessHandler($options),
            failureHandler: $this->createFailureHandler($options),
        );
    }
}
