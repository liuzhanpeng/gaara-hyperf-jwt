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
use GaaraHyperf\Passport\Passport;
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
     * @param AuthenticationSuccessHandlerInterface|null $successHandler
     * @param AuthenticationFailureHandlerInterface|null $failureHandler
     */
    public function __construct(
        private AccessTokenManagerInterface $accessTokenManager,
        private AccessTokenExtractorInterface $accessTokenExtractor,
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
    public function onAuthenticationFailure(string $guardName, ServerRequestInterface $request, AuthenticationException $exception, ?Passport $passport = null): ?ResponseInterface
    {
        if (!is_null($this->failureHandler)) {
            return $this->failureHandler->handle($guardName, $request, $exception, $passport);
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
