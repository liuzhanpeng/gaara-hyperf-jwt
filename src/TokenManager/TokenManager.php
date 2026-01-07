<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\TokenManager;

use DateTimeImmutable;
use GaaraHyperf\Token\TokenInterface;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;

/**
 * 内置的Token管理器
 * 
 * 依赖于lcobucci/jwt
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class TokenManager implements TokenManagerInterface
{
    public function __construct(
        private array $options,
    ) {}

    public function issue(TokenInterface $token): string
    {
        $key = InMemory::base64Encoded($this->options['secret_key']);

        $token = (new JwtFacade())->issue(
            $this->resolveSigner($this->options['algo']),
            $key,
            static fn(
                Builder $builder,
                DateTimeImmutable $issuedAt
            ): Builder => $builder
                ->issuedBy($this->options['iss'])
                ->relatedTo($token->getUserIdentifier())
                ->issuedAt($issuedAt)
                ->expiresAt($issuedAt->modify('+' . $this->options['ttl'] . ' seconds'))
                ->identifiedBy(bin2hex(random_bytes(16)))
        );

        return $token->toString();
    }

    public function resolve(string $accessToken): JWTokenInterface
    {
        throw new \Exception('Not implemented');
    }

    public function revoke(string $accessToken): void {}

    /**
     *
     * @param string $algo
     * @return Signer
     */
    private function resolveSigner(string $algo): Signer
    {
        return match (strtolower($algo)) {
            'sha256' => new Sha256(),
            default => throw new  \InvalidArgumentException("Not found Signer whit: $algo")
        };
    }
}
