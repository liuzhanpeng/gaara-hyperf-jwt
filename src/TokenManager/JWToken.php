<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\TokenManager;

/**
 * 令牌
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWToken implements JWTokenInterface
{
    /**
     * @param string $iss
     * @param string $sub
     * @param string|null $aud
     * @param integer $iat
     * @param integer $exp
     * @param integer|null $nbf
     * @param string $jti
     * @param array $customClaims
     */
    public function __construct(
        private string $iss,
        private string $sub,
        private ?string $aud,
        private int $iat,
        private int $exp,
        private ?int $nbf,
        private string $jti,
        private array $customClaims = []
    ) {}

    /**
     * @inheritDoc
     */
    public function iss(): string
    {
        return $this->iss;
    }

    /**
     * @inheritDoc
     */
    public function sub(): string
    {
        return $this->sub;
    }

    /**
     * @inheritDoc
     */
    public function aud(): ?string
    {
        return $this->aud;
    }

    /**
     * @inheritDoc
     */
    public function iat(): int
    {
        return $this->iat;
    }

    /**
     * @inheritDoc
     */
    public function exp(): int
    {
        return $this->exp;
    }

    /**
     * @inheritDoc
     */
    public function nbf(): ?int
    {
        return $this->nbf;
    }

    /**
     * @inheritDoc
     */
    public function jti(): string
    {
        return $this->jti;
    }

    /**
     * @inheritDoc
     */
    public function customClaims(): array
    {
        return $this->customClaims;
    }
}
