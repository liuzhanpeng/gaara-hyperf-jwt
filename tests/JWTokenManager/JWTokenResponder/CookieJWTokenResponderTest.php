<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\CookieJWTokenResponder;
use GaaraHyperf\JWT\RefreshToken;
use Hyperf\HttpMessage\Cookie\Cookie;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;

it('renders cookie responses even without a refresh token payload', function (): void {
    $response = Mockery::mock(ResponseInterface::class);
    $psrResponse = Mockery::mock(PsrResponseInterface::class);

    $response->shouldReceive('json')->once()->with([
        'code' => 0,
        'message' => 'success',
    ])->andReturn($psrResponse);

    $responder = new CookieJWTokenResponder($response);

    expect($responder->respond(new AccessToken('access-123', 600)))->toBe($psrResponse);
});

it('stores refresh tokens in cookies when using the cookie responder', function (): void {
    $response = Mockery::mock(ResponseInterface::class);
    $psrResponse = Mockery::mock(PsrResponseInterface::class);

    $response->shouldReceive('withCookie')->once()->with(Mockery::on(function (Cookie $cookie): bool {
        return $cookie->getName() === 'refresh_token'
            && $cookie->getValue() === 'refresh-456'
            && $cookie->isHttpOnly();
    }))->andReturnSelf();

    $response->shouldReceive('json')->once()->with([
        'code' => 0,
        'message' => 'success',
    ])->andReturn($psrResponse);

    $responder = new CookieJWTokenResponder($response);

    expect($responder->respond(new AccessToken('access-123', 600), new RefreshToken('refresh-456', 3600)))
        ->toBe($psrResponse);
});
