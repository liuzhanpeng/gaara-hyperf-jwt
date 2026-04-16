<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\JWTokenManager\JWTokenResponder;

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\RefreshToken;
use Psr\Http\Message\ResponseInterface;

/**
 * 令牌响应器接口.
 */
interface JWTokenResponderInterface
{
    public function respond(AccessToken $accessToken, ?RefreshToken $refreshToken = null): ResponseInterface;
}
