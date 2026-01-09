<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorInterface;
use GaaraHyperf\Authenticator\AbstractAuthenticator;
use GaaraHyperf\Authenticator\AuthenticationSuccessHandlerInterface;
use GaaraHyperf\Authenticator\AuthenticationFailureHandlerInterface;
use GaaraHyperf\Exception\AuthenticationException;
use GaaraHyperf\Exception\InvalidCredentialsException;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerInterface;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerInterface;
use GaaraHyperf\Passport\Passport;
use GaaraHyperf\Token\TokenInterface;
use GaaraHyperf\UserProvider\UserProviderInterface;
use Hyperf\HttpMessage\Cookie\Cookie;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * JWT认证器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWTAuthenticator extends AbstractAuthenticator
{
    /**
     * @param AccessTokenManagerInterface $accessTokenManager
     * @param AccessTokenExtractorInterface $accessTokenExtractor
     * @param RefreshTokenManagerInterface $refreshTokenManager
     * @param AccessTokenExtractorInterface $refreshTokenExtractor
     * @param UserProviderInterface $userProvider
     * @param array $options
     * @param AuthenticationSuccessHandlerInterface|null $successHandler
     * @param AuthenticationFailureHandlerInterface|null $failureHandler
     */
    public function __construct(
        private AccessTokenManagerInterface $accessTokenManager,
        private AccessTokenExtractorInterface $accessTokenExtractor,
        private RefreshTokenManagerInterface $refreshTokenManager,
        private AccessTokenExtractorInterface $refreshTokenExtractor,
        private UserProviderInterface $userProvider,
        private array $options,
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
        return $this->accessTokenExtractor->extract($request) !== null
            || ($request->getMethod() === 'POST' && $request->getUri()->getPath() === $this->options['refresh_path']);
    }

    /**
     * @inheritDoc
     */
    public function authenticate(ServerRequestInterface $request): Passport
    {
        if ($request->getUri()->getPath() === $this->options['refresh_path']) {
            $refreshToken = $this->refreshTokenExtractor->extract($request);
            if ($refreshToken === null) {
                throw new InvalidCredentialsException('No refresh token found in the request');
            }

            $token = $this->refreshTokenManager->resolve($refreshToken);
            if (is_null($token)) {
                throw new InvalidCredentialsException('Invalid refresh token');
            }

            return new Passport(
                $token->getUserIdentifier(),
                $this->userProvider->findByIdentifier(...)
            );
        }

        $accessToken = $this->accessTokenExtractor->extract($request);
        if ($accessToken === null) {
            throw new InvalidCredentialsException('No access token found in the request');
        }

        $user = $this->accessTokenManager->parse($accessToken);
        $userIdentifier = $user->getIdentifier();

        return new Passport(
            $userIdentifier,
            fn() => $user
        );
    }

    /**
     * @inheritDoc
     * @override
     */
    public function onAuthenticationSuccess(string $guardName, ServerRequestInterface $request, TokenInterface $token, Passport $passport): ?ResponseInterface
    {
        if (!is_null($this->successHandler)) {
            return $this->successHandler->handle($guardName, $request, $token, $passport);
        }

        if ($request->getUri()->getPath() === $this->options['refresh_path']) {
            $response = new \Hyperf\HttpMessage\Server\Response();
            $refreshToken = $this->refreshTokenManager->issue($token);

            if ($this->options['refresh_token_response_type'] === 'cookie') {
                return $response->withCookie(new Cookie(
                    name: $this->options['refresh_token_name'] ?? 'refresh_token',
                    value: $refreshToken->token(),
                    expire: time() + $refreshToken->expiresIn(),
                    path: $this->options['refresh_token_cookie_path'] ?? '/',
                    domain: $this->options['refresh_token_cookie_domain'] ?? '',
                    httpOnly: true,
                    secure: $this->options['refresh_token_cookie_secure'] ?? true,
                    sameSite: $this->options['refresh_token_cookie_samesite'] ?? 'lax',
                ));
            }

            return $response->withBody(new \Hyperf\HttpMessage\Stream\SwooleStream(json_encode([
                $this->options['refresh_token_name'] ?? 'refresh_token' => $refreshToken->token(),
            ])));
        }

        return null;
    }

    /**
     * @inheritDoc
     * @override
     */
    public function onAuthenticationFailure(string $guardName, ServerRequestInterface $request, AuthenticationException $exception, ?Passport $passport = null): ?ResponseInterface
    {
        if (!is_null($this->failureHandler)) {
            return $this->failureHandler->handle($guardName, $request, $exception, $passport);
        }

        if ($request->getUri()->getPath() === $this->options['refresh_path']) {
            $response = new \Hyperf\HttpMessage\Server\Response();
            return $response->withStatus(401)->withBody(new \Hyperf\HttpMessage\Stream\SwooleStream(json_encode([
                'error' => $exception->getMessage(),
            ])));
        }

        $response = new \Hyperf\HttpMessage\Server\Response();
        return $response->withStatus(401)->withBody(new \Hyperf\HttpMessage\Stream\SwooleStream($exception->getMessage()));
    }

    /**
     * @inheritDoc
     */
    public function isInteractive(): bool
    {
        return false;
    }
}
