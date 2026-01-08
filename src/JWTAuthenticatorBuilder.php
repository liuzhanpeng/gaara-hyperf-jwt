<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorFactory;
use GaaraHyperf\UserProvider\UserProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;
use GaaraHyperf\Authenticator\AuthenticatorInterface;
use GaaraHyperf\Authenticator\Builder\AbstractAuthenticatorBuilder;
use GaaraHyperf\JWT\EventListener\TokenRevokeLogoutListener;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;

/**
 * JWT认证器构建器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWTAuthenticatorBuilder extends AbstractAuthenticatorBuilder
{
    public function create(array $options, UserProviderInterface $userProvider, EventDispatcher $eventDispatcher): AuthenticatorInterface
    {
        $options = array_merge([
            'token_manager' => 'default',
            'token_extractor' => [
                'type' => 'header',
                'param_name' => 'Authorization',
                'param_type' => 'Bearer',
            ],
        ], $options);

        $jwtTokenManager = $this->container->get(AccessTokenManagerResolverInterface::class)->resolve($options['token_manager']);
        $accessTokenExtractorFactory = $this->container->get(AccessTokenExtractorFactory::class);
        $accessTokenExtractor = $accessTokenExtractorFactory->create($options['token_extractor']);

        return new JWTAuthenticator(
            jwtTokenManager: $jwtTokenManager,
            accessTokenExtractor: $accessTokenExtractor,
            successHandler: $this->createSuccessHandler($options),
            failureHandler: $this->createFailureHandler($options),
        );
    }
}
