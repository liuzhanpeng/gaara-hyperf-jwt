<?php

declare(strict_types=1);

use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuer;
use Psr\SimpleCache\CacheInterface;

final class ArrayCache implements CacheInterface
{
    private array $items = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->items[$key] ?? $default;
    }

    public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
    {
        $this->items[$key] = $value;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }

        return $values;
    }

    public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete((string) $key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->items);
    }
}

it('issues and resolves refresh tokens', function (): void {
    $cache = new ArrayCache();
    $issuer = new RefreshTokenIssuer($cache, 'jwt', 3600, false, 64);
    $token = makeTokenMock('user-42');

    $refreshToken = $issuer->issue($token);

    expect(strlen($refreshToken->token()))->toBe(64)
        ->and($refreshToken->expiresIn())->toBe(3600)
        ->and($issuer->resolve($refreshToken->token()))->toBe($token);
});

it('revokes the previous refresh token in single-session mode', function (): void {
    $cache = new ArrayCache();
    $issuer = new RefreshTokenIssuer($cache, 'jwt', 3600, true, 64);
    $token = makeTokenMock('user-42');

    $first = $issuer->issue($token);
    $second = $issuer->issue($token);

    expect($issuer->resolve($first->token()))->toBeNull()
        ->and($issuer->resolve($second->token()))->toBe($token);
});

it('removes refresh tokens when revoked', function (): void {
    $cache = new ArrayCache();
    $issuer = new RefreshTokenIssuer($cache, 'jwt', 3600, true, 64);
    $token = makeTokenMock('user-42');

    $refreshToken = $issuer->issue($token);
    $issuer->revoke($refreshToken->token());

    expect($issuer->resolve($refreshToken->token()))->toBeNull();
});

it('requires a minimum refresh token length', function (): void {
    expect(fn () => new RefreshTokenIssuer(new ArrayCache(), 'jwt', 3600, false, 16))
        ->toThrow(InvalidArgumentException::class, 'at least 32 characters');
});
