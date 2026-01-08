<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticationSuccessHandlerInterface;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
use Psr\Http\Message\ServerRequestInterface;
use GaaraHyperf\Token\TokenInterface;
use GaaraHyperf\Passport\Passport;
use Psr\Http\Message\ResponseInterface;

/**
 * JWT响应处理器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWTResponseHandler implements AuthenticationSuccessHandlerInterface
{
    public function __construct(
        private AccessTokenManagerResolverInterface $accessTokenManagerResolver,
        private \Hyperf\HttpServer\Contract\ResponseInterface $response,
        private string $tokenManager = 'default',
        private ?string $responseTemplate = null,
    ) {}

    public function handle(string $guardName, ServerRequestInterface $request, TokenInterface $token, Passport $passport): ?ResponseInterface
    {
        $accessToken = $this->accessTokenManagerResolver->resolve($this->tokenManager)->issue($token);

        $template = str_replace(
            ['#ACCESS_TOKEN#', '#EXPIRES_IN#'],
            [$accessToken->token(), $accessToken->expiresIn()],
            $this->responseTemplate ?? '{"access_token": "#ACCESS_TOKEN#", "expires_in": #EXPIRES_IN#}'
        );

        if (!is_string($template) || !is_array(json_decode($template, true))) {
            throw new \InvalidArgumentException('Response template must be a valid JSON string');
        }

        $responseData = json_decode($template, true);

        return $this->response->json($responseData);
    }
}
