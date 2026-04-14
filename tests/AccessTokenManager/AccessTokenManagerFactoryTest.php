<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManager;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerFactory;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerInterface;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\Token\TokenInterface;
use Hyperf\Contract\ContainerInterface;

describe('AccessTokenManagerFactory', function () {
    it('creates default access token manager', function () {
        $expected = Mockery::mock(AccessTokenManagerInterface::class);

        $container = Mockery::mock(ContainerInterface::class);
        $container->shouldReceive('make')
            ->once()
            ->with(AccessTokenManager::class, [
                'algo' => 'HS256',
                'secretKey' => str_repeat('a', 64),
                'publicKey' => null,
                'passphrase' => '',
                'ttl' => 600,
                'leeway' => null,
                'iss' => 'issuer',
                'aud' => 'audience',
            ])
            ->andReturn($expected);

        $factory = new AccessTokenManagerFactory($container);

        expect($factory->create([
            'type' => 'default',
            'algo' => 'HS256',
            'secret_key' => str_repeat('a', 64),
            'ttl' => 600,
            'iss' => 'issuer',
            'aud' => 'audience',
        ]))->toBe($expected);
    });

    it('creates custom manager when class implements interface', function () {
        $custom = Mockery::mock(AccessTokenManagerInterface::class);

        $container = Mockery::mock(ContainerInterface::class);
        $container->shouldReceive('make')
            ->once()
            ->with(DummyAccessTokenManager::class, ['fooBar' => 'baz'])
            ->andReturn($custom);

        $factory = new AccessTokenManagerFactory($container);

        expect($factory->create([
            'type' => 'custom',
            'class' => DummyAccessTokenManager::class,
            'params' => ['foo_bar' => 'baz'],
        ]))->toBe($custom);
    });

    it('throws when custom manager does not implement interface', function () {
        $container = Mockery::mock(ContainerInterface::class);
        $container->shouldReceive('make')->once()->andReturn(new stdClass());

        $factory = new AccessTokenManagerFactory($container);

        $factory->create([
            'type' => 'custom',
            'class' => stdClass::class,
        ]);
    })->throws(InvalidArgumentException::class, 'The custom AccessTokenManager must implement');

    it('throws on unsupported manager type', function () {
        $container = Mockery::mock(ContainerInterface::class);
        $factory = new AccessTokenManagerFactory($container);

        $factory->create(['type' => 'unknown']);
    })->throws(InvalidArgumentException::class, 'Unsupported access token manager type: unknown');
});

class DummyAccessTokenManager implements AccessTokenManagerInterface
{
    public function issue(TokenInterface $token, array $customClaims = []): AccessToken
    {
        return new AccessToken('token', 1);
    }

    public function parse(string $accessToken): JWTUser
    {
        return new JWTUser('id', []);
    }
}
