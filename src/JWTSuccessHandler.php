<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticationSuccessHandlerInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerInterface;
use GaaraHyperf\Passport\Passport;
use GaaraHyperf\Token\TokenInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * JWT响应处理器.
 */
class JWTSuccessHandler implements AuthenticationSuccessHandlerInterface
{
    public function __construct(
        private JWTokenManagerInterface $jwTokenManager,
    ) {
    }

    public function handle(string $guardName, ServerRequestInterface $request, TokenInterface $token, Passport $passport): ?ResponseInterface
    {
        $user = $passport->getUser();
        $customClaims = $user instanceof JWTCustomClaimAwareUserInterface ? $user->getJWTCustomClaims() : [];

        return $this->jwTokenManager->issue($token, $customClaims);
    }
}
