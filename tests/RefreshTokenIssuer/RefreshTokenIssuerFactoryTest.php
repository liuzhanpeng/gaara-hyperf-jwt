<?php

declare(strict_types=1);

use GaaraHyperf\Constants;
use GaaraHyperf\JWT\RefreshToken;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuer;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerFactory;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerInterface;
use GaaraHyperf\Token\TokenInterface;
use Hyperf\Contract\ContainerInterface;

final class DummyCustomRefreshTokenIssuerForFactoryTest implements RefreshTokenIssuerInterface
{
    public function issue(TokenInterface $token): RefreshToken
    {
        return new RefreshToken('custom-refresh-token', 123);
    }

    public function resolve(string $refreshToken): ?TokenInterface
    {
        return null;
    }

    public function revoke(string $refreshToken): void
    {
    }
}

it('creates the default refresh token issuer from config', function (): void {
    $expected = Mockery::mock(RefreshTokenIssuerInterface::class);
    $container = Mockery::mock(ContainerInterface::class);

    $container->shouldReceive('make')->once()->with(RefreshTokenIssuer::class, [
        'prefix' => Constants::__PREFIX . ':jwt_refresh_token:guard1',
        'ttl' => 1209600,
        'singleSession' => true,
        'refreshTokenLength' => 64,
    ])->andReturn($expected);

    $factory = new RefreshTokenIssuerFactory($container);

    expect($factory->create([
        'type' => 'default',
        'prefix' => 'guard1',
        'ttl' => 1209600,
        'single_session' => true,
        'refresh_token_length' => 64,
    ]))->toBe($expected);
});

it('creates a custom refresh token issuer from config', function (): void {
    $expected = new DummyCustomRefreshTokenIssuerForFactoryTest();
    $container = Mockery::mock(ContainerInterface::class);

    $container->shouldReceive('make')->once()->with(DummyCustomRefreshTokenIssuerForFactoryTest::class, [
        'fooBar' => 'baz',
    ])->andReturn($expected);

    $factory = new RefreshTokenIssuerFactory($container);

    expect($factory->create([
        'type' => 'custom',
        'class' => DummyCustomRefreshTokenIssuerForFactoryTest::class,
        'params' => ['foo_bar' => 'baz'],
    ]))->toBe($expected);
});

it('rejects custom refresh token issuers that do not implement the interface', function (): void {
    $container = Mockery::mock(ContainerInterface::class);
    $container->shouldReceive('make')->once()->andReturn(new stdClass());

    $factory = new RefreshTokenIssuerFactory($container);

    expect(fn () => $factory->create([
        'type' => 'custom',
        'class' => stdClass::class,
    ]))->toThrow(InvalidArgumentException::class, 'The custom RefreshTokenIssuer must implement');
});

it('rejects unsupported refresh token issuer types', function (): void {
    $factory = new RefreshTokenIssuerFactory(Mockery::mock(ContainerInterface::class));

    expect(fn () => $factory->create(['type' => 'unknown']))
        ->toThrow(InvalidArgumentException::class, 'Unsupported refresh token issuer type: unknown');
});
