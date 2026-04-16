<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AbstractAuthenticator;
use GaaraHyperf\Authenticator\AuthenticationFailureHandlerInterface;
use GaaraHyperf\Authenticator\AuthenticationSuccessHandlerInterface;
use GaaraHyperf\Event\LogoutEvent;
use GaaraHyperf\Exception\InvalidAccessTokenException;
use GaaraHyperf\Exception\InvalidCredentialsException;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerInterface;
use GaaraHyperf\Passport\Passport;
use GaaraHyperf\Token\TokenInterface;
use GaaraHyperf\UserProvider\UserProviderInterface;
use Psr\Http\Message\ResponseInterface as MessageResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * JWT认证器.
 */
class JWTAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private JWTokenManagerInterface $jwTokenManager,
        private UserProviderInterface $userProvider,
        private EventDispatcher $eventDispatcher,
        ?AuthenticationSuccessHandlerInterface $successHandler = null,
        ?AuthenticationFailureHandlerInterface $failureHandler = null
    ) {
        parent::__construct($successHandler, $failureHandler);
    }

    public function supports(ServerRequestInterface $request): bool
    {
        if ($this->jwTokenManager->isRefreshTokenEnabled()
            && $request->getMethod() === 'POST'
            && (
                $request->getUri()->getPath() === $this->jwTokenManager->refreshTokenPath()
                || $request->getUri()->getPath() === $this->jwTokenManager->logoutPath()
            )) {
            return true;
        }

        try {
            return $this->jwTokenManager->resolveAccessToken($request) !== null;
        } catch (InvalidAccessTokenException) {
            return false;
        }
    }

    public function authenticate(ServerRequestInterface $request): Passport
    {
        if ($this->jwTokenManager->isRefreshTokenEnabled()
            && $request->getMethod() === 'POST'
            && (
                $request->getUri()->getPath() === $this->jwTokenManager->refreshTokenPath()
                || $request->getUri()->getPath() === $this->jwTokenManager->logoutPath()
            )) {
            $token = $this->jwTokenManager->resolveRefreshToken($request);
            if (is_null($token)) {
                throw new InvalidCredentialsException('Invalid refresh token');
            }

            return new Passport(
                $token->getUserIdentifier(),
                $this->userProvider->findByIdentifier(...)
            );
        }

        $jwtUser = $this->jwTokenManager->resolveAccessToken($request);
        if ($jwtUser === null) {
            throw new InvalidAccessTokenException('Invalid access token');
        }

        return new Passport(
            $jwtUser->getIdentifier(),
            fn () => $jwtUser
        );
    }

    /**
     * @override
     */
    public function onAuthenticationSuccess(string $guardName, ServerRequestInterface $request, TokenInterface $token, Passport $passport): ?MessageResponseInterface
    {
        if (! is_null($this->successHandler)) {
            return $this->successHandler->handle($guardName, $request, $token, $passport);
        }

        if ($this->jwTokenManager->isRefreshTokenEnabled() && $request->getMethod() === 'POST') {
            if ($request->getUri()->getPath() === $this->jwTokenManager->refreshTokenPath()) { // 简化处理，不定义专门的RefreshToken认证器，
                // 撤消旧的刷新令牌
                $this->jwTokenManager->revokeRefreshToken($request);

                $user = $passport->getUser();
                $customClaims = $user instanceof JWTCustomClaimAwareUserInterface ? $user->getJWTCustomClaims() : [];

                return $this->jwTokenManager->issue($token, $customClaims);
            }
            if ($request->getUri()->getPath() === $this->jwTokenManager->logoutPath()) {
                // 撤消旧的刷新令牌
                $this->jwTokenManager->revokeRefreshToken($request);

                // JWT没有状态，直接分发登出事件
                $logoutEvent = new LogoutEvent($token, $request);
                $this->eventDispatcher->dispatch($logoutEvent);

                return $logoutEvent->getResponse();
            }
        }

        return null;
    }

    public function isInteractive(): bool
    {
        return false;
    }
}
