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
use GaaraHyperf\JWT\Exception\JWTException;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerInterface;
use GaaraHyperf\Passport\Passport;
use GaaraHyperf\Token\TokenInterface;
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
     * @param string $refreshPath
     * @param AccessTokenManagerInterface $accessTokenManager
     * @param AccessTokenExtractorInterface $accessTokenExtractor
     * @param bool $refreshTokenEnabled
     * @param RefreshTokenManagerInterface|null $refreshTokenManager
     * @param AccessTokenExtractorInterface|null $refreshTokenExtractor
     * @param AuthenticationSuccessHandlerInterface|null $successHandler
     * @param AuthenticationFailureHandlerInterface|null $failureHandler
     */
    public function __construct(
        private string $refreshPath,
        private AccessTokenManagerInterface $accessTokenManager,
        private AccessTokenExtractorInterface $accessTokenExtractor,
        private bool $refreshTokenEnabled = true,
        private ?RefreshTokenManagerInterface $refreshTokenManager = null,
        private ?AccessTokenExtractorInterface $refreshTokenExtractor = null,
        ?AuthenticationSuccessHandlerInterface $successHandler = null,
        ?AuthenticationFailureHandlerInterface $failureHandler = null
    ) {
        parent::__construct($successHandler, $failureHandler);
        if ($this->refreshTokenEnabled && empty($this->refreshPath)) {
            throw new \InvalidArgumentException('The "refresh_path" option is required when refresh_token_enabled is true.');
        }
    }

    /**
     * @inheritDoc
     */
    public function supports(ServerRequestInterface $request): bool
    {
        return $this->accessTokenExtractor->extract($request) !== null
            || ($this->refreshTokenEnabled && $request->getMethod() === 'POST' && $request->getUri()->getPath() === $this->refreshPath);
    }

    /**
     * @inheritDoc
     */
    public function authenticate(ServerRequestInterface $request): Passport
    {
        if ($this->refreshTokenEnabled && $request->getUri()->getPath() === $this->refreshPath) {
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
                fn() => $token
            );
        }

        $accessToken = $this->accessTokenExtractor->extract($request);
        if ($accessToken === null) {
            throw new InvalidCredentialsException('No access token found in the request');
        }

        try {
            $user = $this->accessTokenManager->parse($accessToken);
            return new Passport(
                $user->getIdentifier(),
                fn() => $user
            );
        } catch (\RuntimeException $e) {
            throw new JWTException($e->getMessage(), $accessToken);
        }
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

        if ($this->refreshTokenEnabled && $request->getUri()->getPath() === $this->refreshPath) {
            $refreshToken = $this->refreshTokenExtractor->extract($request);
            $this->refreshTokenManager->revoke($refreshToken);

            $response = new \Hyperf\HttpMessage\Server\Response();
            $accessToken = $this->accessTokenManager->issue($token);
            $refreshToken = $this->refreshTokenManager->issue($token);

            return $response->withBody(new \Hyperf\HttpMessage\Stream\SwooleStream(json_encode([
                'access_token' => $accessToken->token(),
                'expires_in' => $accessToken->expiresIn(),
                'refresh_token' => $refreshToken->token(),
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

        if ($this->refreshTokenEnabled && $request->getUri()->getPath() === $this->refreshPath) {
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
