<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorInterface;
use GaaraHyperf\Authenticator\AbstractAuthenticator;
use GaaraHyperf\Authenticator\AuthenticationSuccessHandlerInterface;
use GaaraHyperf\Authenticator\AuthenticationFailureHandlerInterface;
use GaaraHyperf\Exception\InvalidCredentialsException;
use GaaraHyperf\JWT\TokenManager\TokenManagerInterface;
use GaaraHyperf\Passport\Passport;
use Psr\Http\Message\ServerRequestInterface;

/**
 * JWT认证器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWTAuthenticator extends AbstractAuthenticator
{
    /**
     * @param AccessTokenExtractorInterface $accessTokenExtractor
     * @param TokenManagerInterface $tokenManager
     * @param AuthenticationSuccessHandlerInterface|null $successHandler
     * @param AuthenticationFailureHandlerInterface|null $failureHandler
     */
    public function __construct(
        private AccessTokenExtractorInterface $accessTokenExtractor,
        private TokenManagerInterface $tokenManager,
        ?AuthenticationSuccessHandlerInterface $successHandler,
        ?AuthenticationFailureHandlerInterface $failureHandler
    ) {
        parent::__construct($successHandler, $failureHandler);
    }

    /**
     * @inheritDoc
     */
    public function supports(ServerRequestInterface $request): bool
    {
        return $this->accessTokenExtractor->extract($request) !== null;
    }

    /**
     * @inheritDoc
     */
    public function authenticate(ServerRequestInterface $request): Passport
    {
        $accessToken = $this->accessTokenExtractor->extract($request);
        if ($accessToken === null) {
            throw new InvalidCredentialsException('No access token found in the request');
        }

        $jwtToken = $this->tokenManager->resolve($accessToken);
        $userIdentifier = $jwtToken->sub();
        $user = new JWTUser($jwtToken);

        return new Passport(
            $userIdentifier,
            fn() => $user
        );
    }

    /**
     * @inheritDoc
     */
    public function isInteractive(): bool
    {
        return false;
    }
}
