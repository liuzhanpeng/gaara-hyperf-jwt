<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\BodyJWTokenResponder;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\CookieJWTokenResponder;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\JWTokenResponderFactory;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\JWTokenResponderInterface;
use GaaraHyperf\JWT\RefreshToken;
use Hyperf\Contract\ContainerInterface;
use Psr\Http\Message\ResponseInterface;

final class DummyCustomJWTokenResponderForFactoryTest implements JWTokenResponderInterface
{
    public function respond(AccessToken $accessToken, ?RefreshToken $refreshToken = null): ResponseInterface
    {
        return Mockery::mock(ResponseInterface::class);
    }
}

it('creates the body responder from config', function (): void {
    $expected = Mockery::mock(JWTokenResponderInterface::class);
    $container = Mockery::mock(ContainerInterface::class);

    $container->shouldReceive('make')->once()->with(BodyJWTokenResponder::class, [
        'template' => '{"ok":true}',
    ])->andReturn($expected);

    $factory = new JWTokenResponderFactory($container);

    expect($factory->create([
        'type' => 'body',
        'template' => '{"ok":true}',
    ]))->toBe($expected);
});

it('creates the cookie responder from config', function (): void {
    $expected = Mockery::mock(JWTokenResponderInterface::class);
    $container = Mockery::mock(ContainerInterface::class);

    $container->shouldReceive('make')->once()->with(CookieJWTokenResponder::class, [
        'cookieName' => 'rt',
        'cookiePath' => '/auth',
        'cookieDomain' => 'example.com',
        'cookieSecure' => false,
        'cookieHttpOnly' => false,
        'cookieSameSite' => 'strict',
        'template' => '{"ok":true}',
    ])->andReturn($expected);

    $factory = new JWTokenResponderFactory($container);

    expect($factory->create([
        'type' => 'cookie',
        'cookie_name' => 'rt',
        'cookie_path' => '/auth',
        'cookie_domain' => 'example.com',
        'cookie_secure' => false,
        'cookie_http_only' => false,
        'cookie_same_site' => 'strict',
        'template' => '{"ok":true}',
    ]))->toBe($expected);
});

it('creates a custom responder from config', function (): void {
    $expected = new DummyCustomJWTokenResponderForFactoryTest();
    $container = Mockery::mock(ContainerInterface::class);

    $container->shouldReceive('make')->once()->with(DummyCustomJWTokenResponderForFactoryTest::class, [
        'fooBar' => 'baz',
    ])->andReturn($expected);

    $factory = new JWTokenResponderFactory($container);

    expect($factory->create([
        'type' => 'custom',
        'class' => DummyCustomJWTokenResponderForFactoryTest::class,
        'params' => ['foo_bar' => 'baz'],
    ]))->toBe($expected);
});

it('rejects invalid custom responders', function (): void {
    $container = Mockery::mock(ContainerInterface::class);
    $container->shouldReceive('make')->once()->andReturn(new stdClass());

    $factory = new JWTokenResponderFactory($container);

    expect(fn () => $factory->create([
        'type' => 'custom',
        'class' => stdClass::class,
    ]))->toThrow(InvalidArgumentException::class, 'The custom JWTokenResponder must implement');
});

it('rejects unsupported responder types', function (): void {
    $factory = new JWTokenResponderFactory(Mockery::mock(ContainerInterface::class));

    expect(fn () => $factory->create(['type' => 'unknown']))
        ->toThrow(InvalidArgumentException::class, 'JWToken Responder type does not exist: unknown');
});
