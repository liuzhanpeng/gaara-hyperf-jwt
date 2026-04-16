<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\BodyJWTokenResponder;
use GaaraHyperf\JWT\RefreshToken;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;

it('renders a json body response with issued tokens', function (): void {
    $response = Mockery::mock(ResponseInterface::class);
    $psrResponse = Mockery::mock(PsrResponseInterface::class);

    $response->shouldReceive('json')->once()->with([
        'code' => 0,
        'message' => 'success',
        'data' => [
            'access_token' => 'access-123',
            'expires_in' => 600,
            'refresh_token' => 'refresh-456',
            'refresh_expires_in' => 3600,
        ],
    ])->andReturn($psrResponse);

    $responder = new BodyJWTokenResponder($response);

    expect($responder->respond(new AccessToken('access-123', 600), new RefreshToken('refresh-456', 3600)))
        ->toBe($psrResponse);
});

it('rejects invalid json templates in the body responder', function (): void {
    $response = Mockery::mock(ResponseInterface::class);
    $responder = new BodyJWTokenResponder($response, '{invalid-json');

    expect(fn () => $responder->respond(new AccessToken('access-123', 600)))
        ->toThrow(InvalidArgumentException::class, 'Response template must be a valid JSON string');
});
