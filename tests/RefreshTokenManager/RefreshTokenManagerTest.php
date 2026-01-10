<?php

declare(strict_types=1);

use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManager;
use GaaraHyperf\Token\TokenInterface;
use Psr\SimpleCache\CacheInterface;

class MemoryCache implements CacheInterface
{
    public array $store = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->store) ? $this->store[$key] : $default;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->store[$key] = $value;
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->store[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->store = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get((string) $key, $default);
        }

        return $result;
    }

    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
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
        return array_key_exists($key, $this->store);
    }
}

class FakeToken implements TokenInterface
{
    public function __construct(
        private string $guardName,
        private string $userIdentifier,
        private array $attributes = [],
    ) {}

    public function getGuardName(): string
    {
        return $this->guardName;
    }

    public function getUserIdentifier(): string
    {
        return $this->userIdentifier;
    }

    public function hasAttribute(string $name): bool
    {
        return array_key_exists($name, $this->attributes);
    }

    public function getAttribute(string $name): mixed
    {
        return $this->attributes[$name] ?? null;
    }

    public function setAttribute(string $name, mixed $value): void
    {
        $this->attributes[$name] = $value;
    }
}

describe('RefreshTokenManager', function () {
    it('issues and resolves refresh tokens', function () {
        $cache = new MemoryCache();
        $manager = new RefreshTokenManager($cache, 'rt', 600, false, 32);
        $token = new FakeToken('guard', 'user-1');

        $refreshToken = $manager->issue($token);

        expect(strlen($refreshToken->token()))->toBe(32);
        expect($refreshToken->expiresIn())->toBe(600);
        expect($manager->resolve($refreshToken->token()))->toBe($token);
    });

    it('enforces single-session by replacing previous tokens', function () {
        $cache = new MemoryCache();
        $manager = new RefreshTokenManager($cache, 'rt', 600, true, 32);
        $token = new FakeToken('guard', 'user-1');

        $first = $manager->issue($token);
        $second = $manager->issue($token);

        expect($manager->resolve($first->token()))->toBeNull();
        expect($manager->resolve($second->token()))->toBe($token);
        expect($cache->get('rt:user:user-1'))->toBe($second->token());
    });

    it('revokes refresh tokens and clears user mapping when single-session', function () {
        $cache = new MemoryCache();
        $manager = new RefreshTokenManager($cache, 'rt', 600, true, 32);
        $token = new FakeToken('guard', 'user-1');

        $issued = $manager->issue($token);
        $manager->revoke($issued->token());

        expect($manager->resolve($issued->token()))->toBeNull();
        expect($cache->get('rt:user:user-1'))->toBeNull();
    });

    it('validates refresh token length requirement', function () {
        $cache = new MemoryCache();
        new RefreshTokenManager($cache, 'rt', 600, false, 15);
    })->throws(InvalidArgumentException::class, 'even number and not less than 16');
});
