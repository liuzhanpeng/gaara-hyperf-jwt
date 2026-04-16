<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticationSuccessHandlerInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerResolverInterface;
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
        private JWTokenManagerResolverInterface $jwTokenManagerResolver,
        private string $jwtManager = 'default',
    ) {
    }

    public function handle(string $guardName, ServerRequestInterface $request, TokenInterface $token, Passport $passport): ?ResponseInterface
    {
        $user = $passport->getUser();
        $customClaims = $user instanceof JWTCustomClaimAwareUserInterface ? $user->getJWTCustomClaims() : [];

        $jwTokenManager = $this->jwTokenManagerResolver->resolve($this->jwtManager);

        return $jwTokenManager->issue($token, $customClaims);
    }
}
