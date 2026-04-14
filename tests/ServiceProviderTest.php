<?php

declare(strict_types=1);

use GaaraHyperf\Authenticator\AuthenticatorFactory;
use GaaraHyperf\Config\Config;
use GaaraHyperf\Config\ConfigLoaderInterface;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
use GaaraHyperf\JWT\JWTAuthenticatorBuilder;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolverInterface;
use GaaraHyperf\JWT\ServiceProvider;
use Hyperf\Contract\ContainerInterface;

describe('ServiceProvider', function () {
    it('registers resolvers and jwt authenticator builder', function () {
        $config = Mockery::mock(Config::class);
        $config->shouldReceive('serviceConfig')->with('jwt_access_token_managers')->andReturn([]);
        $config->shouldReceive('serviceConfig')->with('jwt_refresh_token_managers')->andReturn([]);

        $loader = Mockery::mock(ConfigLoaderInterface::class);
        $loader->shouldReceive('load')->once()->andReturn($config);

        $authenticatorFactory = Mockery::mock(AuthenticatorFactory::class);
        $authenticatorFactory->shouldReceive('registerBuilder')->once()->with('jwt', JWTAuthenticatorBuilder::class);

        $definitions = [];

        $container = Mockery::mock(ContainerInterface::class);
        $container->shouldReceive('get')->with(ConfigLoaderInterface::class)->andReturn($loader);
        $container->shouldReceive('get')->with(AuthenticatorFactory::class)->andReturn($authenticatorFactory);
        $container->shouldReceive('define')->twice()->andReturnUsing(function (string $name, $definition) use (&$definitions): void {
            $definitions[$name] = $definition;
        });

        $provider = new ServiceProvider();
        $provider->register($container);

        expect($definitions)->toHaveKey(AccessTokenManagerResolverInterface::class);
        expect($definitions)->toHaveKey(RefreshTokenManagerResolverInterface::class);
        expect($definitions[AccessTokenManagerResolverInterface::class])->toBeCallable();
        expect($definitions[RefreshTokenManagerResolverInterface::class])->toBeCallable();
    });
});
