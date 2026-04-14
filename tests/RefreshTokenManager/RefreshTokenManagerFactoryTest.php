<?php

declare(strict_types=1);

use GaaraHyperf\Constants;
use GaaraHyperf\JWT\RefreshToken;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManager;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerFactory;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerInterface;
use GaaraHyperf\Token\TokenInterface;
use Hyperf\Contract\ContainerInterface;

describe('RefreshTokenManagerFactory', function () {
    it('creates default refresh token manager', function () {
        $expected = Mockery::mock(RefreshTokenManagerInterface::class);

        $container = Mockery::mock(ContainerInterface::class);
        $container->shouldReceive('make')
            ->once()
            ->with(RefreshTokenManager::class, [
                'prefix' => Constants::__PREFIX . ':jwt_refresh_token:guard1',
                'ttl' => 3600,
                'singleSession' => true,
                'refreshTokenLength' => 64,
            ])
            ->andReturn($expected);

        $factory = new RefreshTokenManagerFactory($container);

        expect($factory->create([
            'type' => 'default',
            'prefix' => 'guard1',
            'ttl' => 3600,
            'single_session' => true,
            'refresh_token_length' => 64,
        ]))->toBe($expected);
    });

    it('creates custom manager when class implements interface', function () {
        $custom = Mockery::mock(RefreshTokenManagerInterface::class);

        $container = Mockery::mock(ContainerInterface::class);
        $container->shouldReceive('make')
            ->once()
            ->with(DummyRefreshTokenManager::class, ['fooBar' => 'baz'])
            ->andReturn($custom);

        $factory = new RefreshTokenManagerFactory($container);

        expect($factory->create([
            'type' => 'custom',
            'class' => DummyRefreshTokenManager::class,
            'params' => ['foo_bar' => 'baz'],
        ]))->toBe($custom);
    });

    it('throws when custom manager does not implement interface', function () {
        $container = Mockery::mock(ContainerInterface::class);
        $container->shouldReceive('make')->once()->andReturn(new stdClass());

        $factory = new RefreshTokenManagerFactory($container);

        $factory->create([
            'type' => 'custom',
            'class' => stdClass::class,
        ]);
    })->throws(InvalidArgumentException::class, 'The custom RefreshTokenManager must implement');

    it('throws on unsupported manager type', function () {
        $container = Mockery::mock(ContainerInterface::class);
        $factory = new RefreshTokenManagerFactory($container);

        $factory->create(['type' => 'unknown']);
    })->throws(InvalidArgumentException::class, 'Unsupported refresh token manager type: unknown');
});

class DummyRefreshTokenManager implements RefreshTokenManagerInterface
{
    public function issue(TokenInterface $token): RefreshToken
    {
        return new RefreshToken('token', 1);
    }

    public function resolve(string $refreshToken): ?TokenInterface
    {
        return null;
    }

    public function revoke(string $refreshToken): void
    {
    }
}
