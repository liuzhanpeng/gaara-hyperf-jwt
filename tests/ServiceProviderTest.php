<?php

declare(strict_types=1);

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorFactory;
use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorInterface;
use GaaraHyperf\Authenticator\AuthenticatorFactory;
use GaaraHyperf\Config\Config;
use GaaraHyperf\Config\ConfigLoaderInterface;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerFactory;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerInterface;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerResolverInterface;
use GaaraHyperf\JWT\JWTAuthenticatorBuilder;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerResolverInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\JWTokenResponderFactory;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\JWTokenResponderInterface;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerFactory;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerInterface;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerResolverInterface;
use GaaraHyperf\JWT\ServiceProvider;
use Hyperf\Contract\ContainerInterface;

final class ServiceProviderTestContainer implements ContainerInterface
{
    public function __construct(
        private array $entries = [],
        private array $definitions = [],
    ) {
    }

    public function get(string $id)
    {
        if (array_key_exists($id, $this->entries)) {
            $entry = $this->entries[$id];
            return $entry instanceof Closure ? $entry() : $entry;
        }

        if (array_key_exists($id, $this->definitions)) {
            $definition = $this->definitions[$id];
            return $definition instanceof Closure ? $definition() : $definition;
        }

        throw new RuntimeException('Entry not found: ' . $id);
    }

    public function has(string $id): bool
    {
        return array_key_exists($id, $this->entries) || array_key_exists($id, $this->definitions);
    }

    public function make(string $name, array $parameters = [])
    {
        return $this->get($name);
    }

    public function set(string $name, $entry): void
    {
        $this->definitions[$name] = $entry;
    }

    public function unbind(string $name): void
    {
        unset($this->entries[$name], $this->definitions[$name]);
    }

    public function define(string $name, $definition): void
    {
        $this->definitions[$name] = $definition;
    }
}

it('registers resolvers and exposes a working jwt manager resolver', function (): void {
    $config = new Config([], [
        'jwt_managers' => [
            'default' => [
                'secret_key' => str_repeat('a', 64),
                'refresh_token_enabled' => false,
            ],
        ],
    ]);

    $configLoader = Mockery::mock(ConfigLoaderInterface::class);
    $configLoader->shouldReceive('load')->once()->andReturn($config);

    $authenticatorFactory = Mockery::mock(AuthenticatorFactory::class);
    $authenticatorFactory->shouldReceive('registerBuilder')->once()->with('jwt', JWTAuthenticatorBuilder::class);

    $extractor = Mockery::mock(AccessTokenExtractorInterface::class);
    $extractorFactory = Mockery::mock(AccessTokenExtractorFactory::class);
    $extractorFactory->shouldReceive('create')->twice()->andReturn($extractor);

    $accessTokenIssuer = Mockery::mock(AccessTokenIssuerInterface::class);
    $accessTokenIssuerFactory = Mockery::mock(AccessTokenIssuerFactory::class);
    $accessTokenIssuerFactory->shouldReceive('create')->once()->andReturn($accessTokenIssuer);

    $refreshTokenIssuer = Mockery::mock(RefreshTokenIssuerInterface::class);
    $refreshTokenIssuerFactory = Mockery::mock(RefreshTokenIssuerFactory::class);
    $refreshTokenIssuerFactory->shouldReceive('create')->once()->andReturn($refreshTokenIssuer);

    $responder = Mockery::mock(JWTokenResponderInterface::class);
    $responderFactory = Mockery::mock(JWTokenResponderFactory::class);
    $responderFactory->shouldReceive('create')->once()->andReturn($responder);

    $container = new ServiceProviderTestContainer([
        ConfigLoaderInterface::class => $configLoader,
        AuthenticatorFactory::class => $authenticatorFactory,
        AccessTokenExtractorFactory::class => $extractorFactory,
        AccessTokenIssuerFactory::class => $accessTokenIssuerFactory,
        RefreshTokenIssuerFactory::class => $refreshTokenIssuerFactory,
        JWTokenResponderFactory::class => $responderFactory,
    ]);

    (new ServiceProvider())->register($container);

    expect($container->has(AccessTokenIssuerResolverInterface::class))->toBeTrue()
        ->and($container->has(RefreshTokenIssuerResolverInterface::class))->toBeTrue()
        ->and($container->has(JWTokenManagerResolverInterface::class))->toBeTrue();

    $managerResolver = $container->get(JWTokenManagerResolverInterface::class);
    $manager = $managerResolver->resolve('default');

    expect($manager)->toBeInstanceOf(JWTokenManagerInterface::class);
});
