<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenManager;

use DateTimeImmutable;
use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\Exception\JWTException;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\Token\TokenInterface;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Validator;

/**
 * 内置的AccessToken管理器
 * 
 * 依赖于lcobucci/jwt
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class AccessTokenManager implements AccessTokenManagerInterface
{
    /**
     * @param array $options
     */
    public function __construct(
        private array $options,
    ) {}

    /**
     * @inheritDoc
     */
    public function issue(TokenInterface $token): AccessToken
    {
        $signer = $this->createSigner($this->options['algo']);
        $key = $this->createSigningKey($this->options['algo']);

        $builder = Builder::new(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates());
        $now = new DateTimeImmutable();
        $token = $builder
            ->issuedAt($now)
            ->expiresAt($now->modify('+' . $this->options['expires_in'] . ' seconds'))
            ->canOnlyBeUsedAfter($now)
            ->issuedBy($this->options['iss'])
            ->permittedFor($this->options['aud'])
            ->relatedTo($token->getUserIdentifier())
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->getToken($signer, $key);

        /**
         * @var \DateTimeImmutable
         */
        $exp = $token->claims()->get('exp');
        return new AccessToken($token->toString(), $exp->getTimestamp() - $now->getTimestamp());
    }

    /**
     * @inheritDoc
     */
    public function parse(string $accessToken): JWTUser
    {
        $signer = $this->createSigner($this->options['algo']);
        $key = $this->createVerificationKey($this->options['algo']);

        $parser = new Parser(new JoseEncoder());

        try {
            $token = $parser->parse($accessToken);
        } catch (\Throwable $e) {
            throw new JWTException('Failed to parse access token: ' . $e->getMessage());
        }

        if (!$token instanceof UnencryptedToken) {
            throw new JWTException('Invalid access token');
        }

        $userIdentifier = $token->claims()->get('sub');

        $validator = new Validator();
        if (!$validator->validate($token, new SignedWith($signer, $key))) {
            throw new JWTException('Invalid access token signature', $userIdentifier);
        }

        if (!$validator->validate($token, new StrictValidAt(new FrozenClock(new DateTimeImmutable()), $this->options['leeway'] ?? null))) {
            throw new JWTException('Access token is expired or not yet valid', $userIdentifier);
        }

        if (!$validator->validate($token, new IssuedBy($this->options['iss']))) {
            throw new JWTException('Invalid access token issuer', $userIdentifier);
        }

        if (!$validator->validate($token, new PermittedFor($this->options['aud']))) {
            throw new JWTException('Access token not permitted for this audience', $userIdentifier);
        }

        $claims = $token->claims()->all();
        $attributes = array_filter(
            $claims,
            fn($key) => !in_array($key, RegisteredClaims::ALL, true),
            ARRAY_FILTER_USE_KEY
        );

        return new JWTUser($userIdentifier, $attributes);
    }

    /**
     * 创建签名器
     * 
     * @param string $algo
     * @return Signer
     */
    private function createSigner(string $algo): Signer
    {
        return match (strtoupper($algo)) {
            'HS256' => new Signer\Hmac\Sha256(),
            'HS384' => new Signer\Hmac\Sha384(),
            'HS512' => new Signer\Hmac\Sha512(),
            'BLAKE28' => new Signer\Blake2b(),
            'ES256' => new Signer\Ecdsa\Sha256(),
            'ES384' => new Signer\Ecdsa\Sha384(),
            'ES512' => new Signer\Ecdsa\Sha512(),
            'RS256' => new Signer\Rsa\Sha256(),
            'RS384' => new Signer\Rsa\Sha384(),
            'RS512' => new Signer\Rsa\Sha512(),
            'EDDSA' => new Signer\EdDSA(),
            default => throw new  \InvalidArgumentException("Not found Signer whit: $algo")
        };
    }

    /**
     * 创建签名Key
     *
     * @param string $algo
     * @return Key
     */
    private function createSigningKey(string $algo): Key
    {
        if ($this->isAsymmetric($algo)) {
            if (!isset($this->options['private_key']) || empty($this->options['private_key'])) {
                throw new \InvalidArgumentException('Missing private key for asymmetric algorithm');
            }

            return InMemory::base64Encoded(
                $this->options['private_key'],
                $this->options['passphrase'] ?? ''
            );
        }

        return InMemory::base64Encoded($this->options['secret_key']);
    }

    /**
     * 创建验证Key
     *
     * @param string $algo
     * @return Key
     */
    private function createVerificationKey(string $algo): Key
    {
        if ($this->isAsymmetric($algo)) {
            if (!isset($this->options['public_key']) || empty($this->options['public_key'])) {
                throw new \InvalidArgumentException('Missing public key for asymmetric algorithm');
            }

            return InMemory::base64Encoded($this->options['public_key']);
        }

        return InMemory::base64Encoded($this->options['secret_key']);
    }

    /**
     * 判断是否为非对称算法
     *
     * @param string $algo
     * @return boolean
     */
    private function isAsymmetric(string $algo): bool
    {
        return in_array(strtoupper($algo), ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'EDDSA'], true);
    }
}
