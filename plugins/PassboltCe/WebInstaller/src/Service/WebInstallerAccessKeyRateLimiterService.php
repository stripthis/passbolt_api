<?php
declare(strict_types=1);

/**
 * Passbolt ~ Open source password manager for teams
 * Copyright (c) Passbolt SA (https://www.passbolt.com)
 *
 * Licensed under GNU Affero General Public License version 3 of the or any later version.
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
 * @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
 * @link          https://www.passbolt.com Passbolt(tm)
 * @since         5.18.0
 */
namespace Passbolt\WebInstaller\Service;

use App\Middleware\HttpProxyMiddleware;
use Cake\Core\Configure;
use Cake\Http\ServerRequest;
use Cake\Validation\Validation;
use Psr\Http\Message\ServerRequestInterface;

class WebInstallerAccessKeyRateLimiterService
{
    private const CONFIG_PREFIX = 'passbolt.webInstaller.rateLimit';
    private const IP_STORAGE_FILE = 'webinstaller_rate_limit.json';
    private const SESSION_KEY = 'webinstaller.accessKeyAttempts';

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @return bool
     */
    public function isLimited(ServerRequestInterface $request): bool
    {
        $sessionAttempts = $this->readSessionAttempts($request);
        if ($sessionAttempts['expires'] > time() && $sessionAttempts['count'] >= $this->getSessionMaxAttempts()) {
            return true;
        }

        $ipKey = $this->getIpBucketKey($request);
        if ($ipKey === null) {
            return true;
        }
        $ipAttempts = $this->withIpStorageLock(function (array &$storage) use ($ipKey): array {
            return $storage[$ipKey] ?? ['count' => 0, 'expires' => 0];
        });

        return $ipAttempts['expires'] > time() && $ipAttempts['count'] >= $this->getIpMaxAttempts();
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @return bool
     */
    public function recordFailure(ServerRequestInterface $request): bool
    {
        $sessionAttempts = $this->readSessionAttempts($request);
        if ($sessionAttempts['expires'] <= time()) {
            $sessionAttempts = [
                'count' => 0,
                'expires' => time() + $this->getCooldown(),
            ];
        }
        $sessionAttempts['count']++;
        $this->writeSessionAttempts($request, $sessionAttempts);
        $sessionLimited = $sessionAttempts['count'] >= $this->getSessionMaxAttempts();

        $ipKey = $this->getIpBucketKey($request);
        if ($ipKey === null) {
            return true;
        }
        $ipAttempts = $this->withIpStorageLock(function (array &$storage) use ($ipKey): array {
            $attempts = $storage[$ipKey] ?? ['count' => 0, 'expires' => 0];
            if ($attempts['expires'] <= time()) {
                $attempts = [
                    'count' => 0,
                    'expires' => time() + $this->getCooldown(),
                ];
            }
            $attempts['count']++;
            $storage[$ipKey] = $attempts;

            return $attempts;
        });
        $ipLimited = $ipAttempts['count'] >= $this->getIpMaxAttempts();

        return $sessionLimited || $ipLimited;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @return void
     */
    public function clear(ServerRequestInterface $request): void
    {
        $this->deleteSessionAttempts($request);
        $ipKey = $this->getIpBucketKey($request);
        if ($ipKey === null) {
            return;
        }
        $this->withIpStorageLock(function (array &$storage) use ($ipKey): array {
            unset($storage[$ipKey]);

            return ['count' => 0, 'expires' => 0];
        });
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @return array{count:int,expires:int}
     */
    private function readSessionAttempts(ServerRequestInterface $request): array
    {
        if (!$request instanceof ServerRequest) {
            return ['count' => 0, 'expires' => 0];
        }

        $attempts = $request->getSession()->read(self::SESSION_KEY);
        if (!is_array($attempts) || !isset($attempts['count'], $attempts['expires'])) {
            return ['count' => 0, 'expires' => 0];
        }

        return [
            'count' => (int)$attempts['count'],
            'expires' => (int)$attempts['expires'],
        ];
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @param array{count:int,expires:int} $attempts Attempts payload.
     * @return void
     */
    private function writeSessionAttempts(ServerRequestInterface $request, array $attempts): void
    {
        if (!$request instanceof ServerRequest) {
            return;
        }

        $request->getSession()->write(self::SESSION_KEY, $attempts);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @return void
     */
    private function deleteSessionAttempts(ServerRequestInterface $request): void
    {
        if (!$request instanceof ServerRequest) {
            return;
        }

        $request->getSession()->delete(self::SESSION_KEY);
    }

    /**
     * @param callable $callback Callback receiving the pruned IP storage by reference.
     * @return array{count:int,expires:int}
     */
    private function withIpStorageLock(callable $callback): array
    {
        $storagePath = TMP . self::IP_STORAGE_FILE;
        $handle = fopen($storagePath, 'c+b');
        if ($handle === false) {
            return $this->getBlockedAttempts();
        }

        if (flock($handle, LOCK_EX) === false) {
            fclose($handle);

            return $this->getBlockedAttempts();
        }
        rewind($handle);
        $contents = stream_get_contents($handle);
        $storage = $this->decodeStorage($contents === false ? '' : $contents);
        $storage = $this->pruneExpiredBuckets($storage);
        $result = $callback($storage);

        $writeSucceeded = ftruncate($handle, 0) !== false;
        $writeSucceeded = $writeSucceeded && rewind($handle);
        $encodedStorage = json_encode($storage);
        $writeSucceeded = $writeSucceeded && $encodedStorage !== false;
        $writeSucceeded = $writeSucceeded && fwrite($handle, $encodedStorage) !== false;
        $writeSucceeded = $writeSucceeded && fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        return $writeSucceeded ? $result : $this->getBlockedAttempts();
    }

    /**
     * @param string $encodedStorage Encoded storage payload.
     * @return array<string, array{count:int,expires:int}>
     */
    private function decodeStorage(string $encodedStorage): array
    {
        $storage = json_decode($encodedStorage, true);
        if (!is_array($storage)) {
            return [];
        }

        $decoded = [];
        foreach ($storage as $bucketKey => $attempts) {
            if (!is_string($bucketKey) || !is_array($attempts) || !isset($attempts['count'], $attempts['expires'])) {
                continue;
            }
            $decoded[$bucketKey] = [
                'count' => (int)$attempts['count'],
                'expires' => (int)$attempts['expires'],
            ];
        }

        return $decoded;
    }

    /**
     * @param array<string, array{count:int,expires:int}> $storage Storage payload.
     * @return array<string, array{count:int,expires:int}>
     */
    private function pruneExpiredBuckets(array $storage): array
    {
        $now = time();

        return array_filter($storage, fn(array $attempts): bool => $attempts['expires'] > $now);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @return string
     */
    private function getIpBucketKey(ServerRequestInterface $request): ?string
    {
        $remoteAddress = $request instanceof ServerRequest ? $request->getServerParams()['REMOTE_ADDR'] ?? null : null;
        if (!is_string($remoteAddress) || !Validation::ip($remoteAddress)) {
            return null;
        }
        if ($request instanceof ServerRequest && $this->canUseTrustedProxyClientIp($request)) {
            $clientIp = $request->clientIp();
            if (is_string($clientIp) && Validation::ip($clientIp)) {
                $remoteAddress = $clientIp;
            }
        }

        return sha1($remoteAddress);
    }

    /**
     * @param \Cake\Http\ServerRequest $request The current request.
     * @return bool
     */
    private function canUseTrustedProxyClientIp(ServerRequest $request): bool
    {
        if (!Configure::read(HttpProxyMiddleware::PASSBOLT_SECURITY_PROXIES_ACTIVE_CONFIG_NAME)) {
            return false;
        }

        $trustedProxiesConfig = Configure::read(HttpProxyMiddleware::PASSBOLT_SECURITY_PROXIES_TRUSTED_PROXIES_CONFIG_NAME);
        if (is_string($trustedProxiesConfig)) {
            $trustedProxiesConfig = explode(',', $trustedProxiesConfig);
        }
        if (!is_array($trustedProxiesConfig)) {
            return false;
        }

        $trustedProxies = array_filter(array_map(
            static fn(mixed $proxy): string => is_string($proxy) ? trim($proxy) : '',
            $trustedProxiesConfig,
        ), static fn(string $proxy): bool => Validation::ip($proxy));
        if (empty($trustedProxies)) {
            return false;
        }

        return in_array($request->getServerParams()['REMOTE_ADDR'] ?? null, $trustedProxies, true);
    }

    /**
     * @return array{count:int,expires:int}
     */
    private function getBlockedAttempts(): array
    {
        return ['count' => PHP_INT_MAX, 'expires' => PHP_INT_MAX];
    }

    /**
     * @return int
     */
    private function getSessionMaxAttempts(): int
    {
        $maxAttempts = Configure::read(self::CONFIG_PREFIX . '.maxAttempts');

        return is_int($maxAttempts) && $maxAttempts > 0 ? $maxAttempts : 5;
    }

    /**
     * @return int
     */
    private function getIpMaxAttempts(): int
    {
        $maxAttempts = Configure::read(self::CONFIG_PREFIX . '.ipMaxAttempts');

        return is_int($maxAttempts) && $maxAttempts > 0 ? $maxAttempts : 20;
    }

    /**
     * @return int
     */
    private function getCooldown(): int
    {
        $cooldown = Configure::read(self::CONFIG_PREFIX . '.cooldown');

        return is_int($cooldown) && $cooldown > 0 ? $cooldown : 300;
    }
}
