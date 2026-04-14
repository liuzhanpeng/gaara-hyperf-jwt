<?php

declare(strict_types=1);

use GaaraHyperf\Token\TokenInterface;
use Mockery\MockInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

afterEach(function (): void {
    Mockery::close();
});

function makeRequest(string $method = 'GET', string $path = '/'): ServerRequestInterface
{
    /** @var MockInterface&ServerRequestInterface $request */
    $request = Mockery::mock(ServerRequestInterface::class);
    /** @var MockInterface&UriInterface $uri */
    $uri = Mockery::mock(UriInterface::class);

    $request->shouldReceive('getMethod')->andReturn($method);
    $request->shouldReceive('getUri')->andReturn($uri);
    $uri->shouldReceive('getPath')->andReturn($path);

    return $request;
}

function makeTokenMock(string $userIdentifier = 'user-1', string $guard = 'guard'): TokenInterface
{
    /** @var MockInterface&TokenInterface $token */
    $token = Mockery::mock(TokenInterface::class);
    $token->shouldReceive('getGuardName')->andReturn($guard);
    $token->shouldReceive('getUserIdentifier')->andReturn($userIdentifier);
    $token->shouldReceive('hasAttribute')->andReturn(false);
    $token->shouldReceive('getAttribute')->andReturn(null);
    $token->shouldReceive('setAttribute')->andReturnNull();

    return $token;
}
