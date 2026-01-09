<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorFactory;
use GaaraHyperf\UserProvider\UserProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;
use GaaraHyperf\Authenticator\AuthenticatorInterface;
use GaaraHyperf\Authenticator\Builder\AbstractAuthenticatorBuilder;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManager;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolverInterface;

/**
 * JWT认证器构建器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWTAuthenticatorBuilder extends AbstractAuthenticatorBuilder
{
    public function create(array $options, UserProviderInterface $userProvider, EventDispatcher $eventDispatcher): AuthenticatorInterface
    {
        $options = array_replace_recursive([
            'access_token_manager' => 'default',
            'access_token_extractor' => [
                'type' => 'header',
                'param_name' => 'Authorization',
                'param_type' => 'Bearer',
            ],
            'refresh_token_manager' => 'default',
            'refresh_token_extractor' => [
                'type' => 'header',
                'param_name' => 'refresh_token',
            ],
            'refresh_token_param_name' => 'refresh_token',
            'refresh_token_response_type' => 'body',
            'refresh_token_cookie_path' => '/',
            'refresh_token_cookie_domain' => null,
            'refresh_token_cookie_secure' => true,
            'refresh_token_cookie_samesite' => 'lax',
        ], $options);

        if (!isset($options['refresh_path'])) {
            throw new \InvalidArgumentException('The "refresh_path" option is required.');
        }

        $accessTokenManager = $this->container->get(AccessTokenManagerResolverInterface::class)->resolve($options['access_token_manager']);
        $refreshTokenManager = $this->container->get(RefreshTokenManagerResolverInterface::class)->resolve($options['refresh_token_manager']);
        $accessTokenExtractorFactory = $this->container->get(AccessTokenExtractorFactory::class);
        $accessTokenExtractor = $accessTokenExtractorFactory->create($options['access_token_extractor']);
        $refreshTokenExtractor = $accessTokenExtractorFactory->create($options['refresh_token_extractor']);

        return new JWTAuthenticator(
            accessTokenManager: $accessTokenManager,
            accessTokenExtractor: $accessTokenExtractor,
            refreshTokenManager: $refreshTokenManager,
            refreshTokenExtractor: $refreshTokenExtractor,
            userProvider: $userProvider,
            options: $options,
            successHandler: $this->createSuccessHandler($options),
            failureHandler: $this->createFailureHandler($options),
        );
    }
}
