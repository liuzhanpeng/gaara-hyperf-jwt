<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuer;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerFactory;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerInterface;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\Token\TokenInterface;
use Hyperf\Contract\ContainerInterface;

final class DummyCustomAccessTokenIssuerForFactoryTest implements AccessTokenIssuerInterface
{
    public function issue(TokenInterface $token, array $customClaims = []): AccessToken
    {
        return new AccessToken('custom-access-token', 123);
    }

    public function resolve(string $accessToken): JWTUser
    {
        return new JWTUser('user-1', []);
    }
}

it('creates the default access token issuer from config', function (): void {
    $expected = Mockery::mock(AccessTokenIssuerInterface::class);
    $container = Mockery::mock(ContainerInterface::class);

    $container->shouldReceive('make')->once()->with(AccessTokenIssuer::class, [
        'algo' => 'HS256',
        'secretKey' => str_repeat('a', 64),
        'publicKey' => null,
        'passphrase' => '',
        'ttl' => 600,
        'leeway' => 5,
        'iss' => 'issuer',
        'aud' => 'audience',
    ])->andReturn($expected);

    $factory = new AccessTokenIssuerFactory($container);

    expect($factory->create([
        'type' => 'default',
        'algo' => 'HS256',
        'secret_key' => str_repeat('a', 64),
        'ttl' => 600,
        'leeway' => 5,
        'iss' => 'issuer',
        'aud' => 'audience',
    ]))->toBe($expected);
});

it('creates a custom access token issuer from config', function (): void {
    $expected = new DummyCustomAccessTokenIssuerForFactoryTest();
    $container = Mockery::mock(ContainerInterface::class);

    $container->shouldReceive('make')->once()->with(DummyCustomAccessTokenIssuerForFactoryTest::class, [
        'fooBar' => 'baz',
    ])->andReturn($expected);

    $factory = new AccessTokenIssuerFactory($container);

    expect($factory->create([
        'type' => 'custom',
        'class' => DummyCustomAccessTokenIssuerForFactoryTest::class,
        'params' => ['foo_bar' => 'baz'],
    ]))->toBe($expected);
});

it('rejects custom access token issuers that do not implement the interface', function (): void {
    $container = Mockery::mock(ContainerInterface::class);
    $container->shouldReceive('make')->once()->andReturn(new stdClass());

    $factory = new AccessTokenIssuerFactory($container);

    expect(fn () => $factory->create([
        'type' => 'custom',
        'class' => stdClass::class,
    ]))->toThrow(InvalidArgumentException::class, 'The custom AccessTokenIssuer must implement');
});

it('rejects unsupported access token issuer types', function (): void {
    $factory = new AccessTokenIssuerFactory(Mockery::mock(ContainerInterface::class));

    expect(fn () => $factory->create(['type' => 'unknown']))
        ->toThrow(InvalidArgumentException::class, 'Unsupported access token issuer type: unknown');
});
