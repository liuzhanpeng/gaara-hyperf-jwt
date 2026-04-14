<?php

declare(strict_types=1);

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorFactory;
use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorInterface;
use GaaraHyperf\Event\LogoutEvent;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerInterface;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
use GaaraHyperf\JWT\JWTAuthenticator;
use GaaraHyperf\JWT\JWTAuthenticatorBuilder;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerInterface;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolverInterface;
use GaaraHyperf\UserProvider\UserProviderInterface;
use Hyperf\Contract\ContainerInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;

describe('JWTAuthenticatorBuilder', function () {
    it('creates authenticator with default options when refresh is disabled', function () {
        $container = Mockery::mock(ContainerInterface::class);

        $accessManager = Mockery::mock(AccessTokenManagerInterface::class);
        $accessManagerResolver = Mockery::mock(AccessTokenManagerResolverInterface::class);
        $accessManagerResolver->shouldReceive('resolve')->once()->with('default')->andReturn($accessManager);

        $extractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $extractorFactory = Mockery::mock(AccessTokenExtractorFactory::class);
        $extractorFactory->shouldReceive('create')
            ->once()
            ->with([
                'type' => 'header',
                'field' => 'Authorization',
                'scheme' => 'Bearer',
            ])
            ->andReturn($extractor);

        $container->shouldReceive('get')->with(AccessTokenManagerResolverInterface::class)->andReturn($accessManagerResolver);
        $container->shouldReceive('get')->with(AccessTokenExtractorFactory::class)->andReturn($extractorFactory);
        $container->shouldReceive('get')->with(RefreshTokenManagerResolverInterface::class)->never();
        $container->shouldReceive('make')->never();

        $builder = new JWTAuthenticatorBuilder($container);
        $authenticator = $builder->create(
            ['refresh_token_enabled' => false],
            Mockery::mock(UserProviderInterface::class),
            new EventDispatcher(),
        );

        expect($authenticator)->toBeInstanceOf(JWTAuthenticator::class);
    });

    it('throws when refresh is enabled and refresh_path is missing', function () {
        $container = Mockery::mock(ContainerInterface::class);
        $builder = new JWTAuthenticatorBuilder($container);

        $builder->create(
            ['refresh_token_enabled' => true],
            Mockery::mock(UserProviderInterface::class),
            new EventDispatcher(),
        );
    })->throws(InvalidArgumentException::class, 'The "refresh_path" option is required when refresh_token_enabled is true.');

    it('registers logout subscriber when refresh is enabled', function () {
        $container = Mockery::mock(ContainerInterface::class);

        $accessManager = Mockery::mock(AccessTokenManagerInterface::class);
        $accessManagerResolver = Mockery::mock(AccessTokenManagerResolverInterface::class);
        $accessManagerResolver->shouldReceive('resolve')->once()->with('default')->andReturn($accessManager);

        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManagerResolver = Mockery::mock(RefreshTokenManagerResolverInterface::class);
        $refreshManagerResolver->shouldReceive('resolve')->once()->with('default')->andReturn($refreshManager);

        $accessExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $refreshExtractor = Mockery::mock(AccessTokenExtractorInterface::class);

        $extractorFactory = Mockery::mock(AccessTokenExtractorFactory::class);
        $extractorFactory->shouldReceive('create')
            ->once()
            ->with([
                'type' => 'header',
                'field' => 'Authorization',
                'scheme' => 'Bearer',
            ])
            ->andReturn($accessExtractor);
        $extractorFactory->shouldReceive('create')
            ->once()
            ->with([
                'type' => 'body',
                'field' => 'refresh_token',
            ])
            ->andReturn($refreshExtractor);

        $container->shouldReceive('get')->with(AccessTokenManagerResolverInterface::class)->andReturn($accessManagerResolver);
        $container->shouldReceive('get')->with(AccessTokenExtractorFactory::class)->andReturn($extractorFactory);
        $container->shouldReceive('get')->with(RefreshTokenManagerResolverInterface::class)->andReturn($refreshManagerResolver);
        $container->shouldReceive('make')->never();

        $dispatcher = new EventDispatcher();
        $builder = new JWTAuthenticatorBuilder($container);

        $authenticator = $builder->create(
            ['refresh_token_enabled' => true, 'refresh_path' => '/api/refresh'],
            Mockery::mock(UserProviderInterface::class),
            $dispatcher,
        );

        expect($authenticator)->toBeInstanceOf(JWTAuthenticator::class);
        expect($dispatcher->getListeners(LogoutEvent::class))->toHaveCount(1);
    });
});
