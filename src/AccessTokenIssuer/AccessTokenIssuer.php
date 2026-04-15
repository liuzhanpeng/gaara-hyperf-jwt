<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenIssuer;

use DateTimeImmutable;
use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\Exception\InvalidAccessTokenException;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\Token\TokenInterface;
use InvalidArgumentException;
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
use Throwable;

/**
 * 内置的AccessToken发行器.
 *
 * 依赖于lcobucci/jwt
 */
class AccessTokenIssuer implements AccessTokenIssuerInterface
{
    /**
     * @param string $algo 签名算法
     * @param string $secretKey 对称算法密钥 或 非对称算法私钥
     * @param null|string $publicKey 非对称算法公钥
     * @param string $passphrase 非对称算法私钥密码
     * @param int $ttl Access Token 有效期，单位：秒
     * @param null|int $leeway 允许的时间偏差，单位：秒
     * @param string $iss Issuer 声明
     * @param string $aud Audience 声明
     */
    public function __construct(
        private string $algo,
        private string $secretKey,
        private ?string $publicKey,
        private string $passphrase,
        private int $ttl,
        private ?int $leeway,
        private string $iss,
        private string $aud,
    ) {
        $this->algo = strtoupper($this->algo);

        if (empty($this->secretKey)) {
            throw new InvalidArgumentException('Missing secret key');
        }

        if ($this->isAsymmetric() && empty($this->publicKey)) {
            throw new InvalidArgumentException('Missing public key for asymmetric algorithm');
        }

        $this->checkSecretKeyLength();
    }

    public function issue(TokenInterface $token, array $customClaims = []): AccessToken
    {
        $signer = $this->getSigner();
        $key = $this->getSigningKey();

        $builder = Builder::new(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates());
        $now = new DateTimeImmutable();
        $builder = $builder
            ->issuedAt($now)
            ->expiresAt($now->modify('+' . $this->ttl . ' seconds'))
            ->canOnlyBeUsedAfter($now)
            ->issuedBy($this->iss)
            ->permittedFor($this->aud)
            ->relatedTo($token->getUserIdentifier())
            ->identifiedBy(bin2hex(random_bytes(16)));

        foreach ($customClaims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        $token = $builder->getToken($signer, $key);

        return new AccessToken($token->toString(), $this->ttl);
    }

    public function parse(string $accessToken): JWTUser
    {
        try {
            $signer = $this->getSigner();
            $key = $this->getVerificationKey();
            $parser = new Parser(new JoseEncoder());
            $token = $parser->parse($accessToken);
        } catch (Throwable $e) {
            throw new InvalidAccessTokenException('Failed to parse access token: ' . $e->getMessage());
        }

        if (! $token instanceof UnencryptedToken) {
            throw new InvalidAccessTokenException('Invalid access token format');
        }

        $userIdentifier = $token->claims()->get('sub');

        $validator = new Validator();
        if (! $validator->validate($token, new SignedWith($signer, $key))) {
            throw new InvalidAccessTokenException('Invalid access token signature');
        }

        if (! $validator->validate($token, new StrictValidAt(new FrozenClock(new DateTimeImmutable()), $this->leeway))) {
            throw new InvalidAccessTokenException('Access token is expired or not yet valid');
        }

        if (! $validator->validate($token, new IssuedBy($this->iss))) {
            throw new InvalidAccessTokenException('Invalid access token issuer');
        }

        if (! $validator->validate($token, new PermittedFor($this->aud))) {
            throw new InvalidAccessTokenException('Access token not permitted for this audience');
        }

        $claims = $token->claims()->all();
        $attributes = array_filter(
            $claims,
            fn ($key) => ! in_array($key, RegisteredClaims::ALL, true),
            ARRAY_FILTER_USE_KEY
        );

        return new JWTUser($userIdentifier, $attributes);
    }

    private function getSigner(): Signer
    {
        return match ($this->algo) {
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
            default => throw new InvalidArgumentException("Not found Signer whit: {$this->algo}")
        };
    }

    private function getSigningKey(): Key
    {
        if ($this->isAsymmetric($this->algo)) {
            return InMemory::plainText($this->secretKey, $this->passphrase);
        }

        return InMemory::plainText($this->secretKey);
    }

    private function getVerificationKey(): Key
    {
        if ($this->isAsymmetric($this->algo)) {
            return InMemory::plainText($this->publicKey);
        }

        return InMemory::plainText($this->secretKey);
    }

    /**
     * 判断是否为非对称算法.
     */
    private function isAsymmetric(): bool
    {
        return in_array($this->algo, ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'EDDSA'], true);
    }

    /**
     * 检查算法对应密钥长度.
     */
    private function checkSecretKeyLength(): void
    {
        switch ($this->algo) {
            case 'HS256':
                $minLength = 32; // 256 bits
                break;
            case 'HS384':
                $minLength = 48; // 384 bits
                break;
            case 'HS512':
                $minLength = 64; // 512 bits
                break;
            case 'BLAKE28':
                $minLength = 32; // 256 bits
                break;
            case 'ES256':
                $minLength = 32; // 256 bits
                break;
            case 'ES384':
                $minLength = 48; // 384 bits
                break;
            case 'ES512':
                $minLength = 66; // 521 bits
                break;
            case 'RS256':
            case 'RS384':
            case 'RS512':
                $minLength = 256; // 2048 bits
                break;
            case 'EDDSA':
                $minLength = 32; // 256 bits
                break;
            default:
                return;
        }

        if (strlen($this->secretKey) < $minLength) {
            throw new InvalidArgumentException(sprintf('The secret key for %s algorithm must be at least %d bytes long.', $this->algo, $minLength));
        }
    }
}
