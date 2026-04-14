<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorFactory;
use GaaraHyperf\Authenticator\AuthenticatorInterface;
use GaaraHyperf\Authenticator\Builder\AbstractAuthenticatorBuilder;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
use GaaraHyperf\JWT\EventListener\JWTRevokeLogoutListener;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolverInterface;
use GaaraHyperf\UserProvider\UserProviderInterface;
use InvalidArgumentException;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * JWT认证器构建器.
 */
class JWTAuthenticatorBuilder extends AbstractAuthenticatorBuilder
{
    public function create(array $options, UserProviderInterface $userProvider, EventDispatcher $eventDispatcher): AuthenticatorInterface
    {
        $options = $options + [
            'access_token_manager' => 'default',
            'access_token_extractor' => [
                'type' => 'header',
                'field' => 'Authorization',
                'scheme' => 'Bearer',
            ],
            'refresh_token_manager' => 'default',
            'refresh_token_extractor' => [
                'type' => 'body',
                'field' => 'refresh_token',
            ],
            'refresh_token_enabled' => true,
        ];

        $refreshTokenEnabled = $options['refresh_token_enabled'];

        if ($refreshTokenEnabled && ! isset($options['refresh_path'])) {
            throw new InvalidArgumentException('The "refresh_path" option is required when refresh_token_enabled is true.');
        }

        $accessTokenManager = $this->container->get(AccessTokenManagerResolverInterface::class)->resolve($options['access_token_manager']);

        $accessTokenExtractorFactory = $this->container->get(AccessTokenExtractorFactory::class);
        $accessTokenExtractor = $accessTokenExtractorFactory->create($options['access_token_extractor']);

        $refreshTokenManager = null;
        $refreshTokenExtractor = null;
        if ($refreshTokenEnabled) {
            $refreshTokenManager = $this->container->get(RefreshTokenManagerResolverInterface::class)->resolve($options['refresh_token_manager']);
            $refreshTokenExtractor = $accessTokenExtractorFactory->create($options['refresh_token_extractor']);

            $eventDispatcher->addSubscriber(new JWTRevokeLogoutListener(
                refreshTokenManager: $refreshTokenManager,
                refreshTokenExtractor: $refreshTokenExtractor,
            ));
        }

        return new JWTAuthenticator(
            refreshPath: $options['refresh_path'] ?? '',
            accessTokenManager: $accessTokenManager,
            accessTokenExtractor: $accessTokenExtractor,
            refreshTokenEnabled: $refreshTokenEnabled,
            refreshTokenManager: $refreshTokenManager,
            refreshTokenExtractor: $refreshTokenExtractor,
            successHandler: $this->createSuccessHandler($options),
            failureHandler: $this->createFailureHandler($options),
        );
    }
}
