<?php

declare(strict_types=1);

use GaaraHyperf\Event\LogoutEvent;
use GaaraHyperf\JWT\JWTAuthenticator;
use GaaraHyperf\JWT\JWTAuthenticatorBuilder;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerResolverInterface;
use GaaraHyperf\UserProvider\UserProviderInterface;
use Hyperf\Contract\ContainerInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;

it('creates a jwt authenticator with the default manager', function (): void {
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);
    $resolver = Mockery::mock(JWTokenManagerResolverInterface::class);
    $userProvider = Mockery::mock(UserProviderInterface::class);
    $container = Mockery::mock(ContainerInterface::class);

    $resolver->shouldReceive('resolve')->once()->with('default')->andReturn($jwtManager);
    $container->shouldReceive('get')->once()->with(JWTokenManagerResolverInterface::class)->andReturn($resolver);

    $builder = new JWTAuthenticatorBuilder($container);
    $dispatcher = new EventDispatcher();

    expect($builder->create([], $userProvider, $dispatcher))->toBeInstanceOf(JWTAuthenticator::class)
        ->and($dispatcher->getListeners(LogoutEvent::class))->toHaveCount(1);
});

it('uses the named jwt manager from the options', function (): void {
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);
    $resolver = Mockery::mock(JWTokenManagerResolverInterface::class);
    $userProvider = Mockery::mock(UserProviderInterface::class);
    $container = Mockery::mock(ContainerInterface::class);

    $resolver->shouldReceive('resolve')->once()->with('api')->andReturn($jwtManager);
    $container->shouldReceive('get')->once()->with(JWTokenManagerResolverInterface::class)->andReturn($resolver);

    $builder = new JWTAuthenticatorBuilder($container);

    expect($builder->create(['jwt_manager' => 'api'], $userProvider, new EventDispatcher()))
        ->toBeInstanceOf(JWTAuthenticator::class);
});
