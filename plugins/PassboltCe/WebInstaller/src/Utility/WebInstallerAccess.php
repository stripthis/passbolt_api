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
namespace Passbolt\WebInstaller\Utility;

use Cake\Core\Configure;
use Cake\Http\Exception\ForbiddenException;
use Cake\Http\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;

class WebInstallerAccess
{
    private const ACCESS_AUTHORIZED_SESSION_KEY = 'webinstaller.accessAuthorized';
    private const ACCESS_KEY_CONFIG = 'passbolt.webInstaller.accessKey';
    private const ACCESS_KEY_HEADER = 'X-Passbolt-Installer-Secret';
    private const ACCESS_KEY_FIELD = 'installer_secret';
    private const DISABLED_ERROR_MESSAGE = 'The web installer is disabled until an installer access key is configured.';
    private const INVALID_ACCESS_KEY_ERROR_MESSAGE = 'The web installer can only be accessed with a valid installer access key.';

    /**
     * Ensure that the web installer can only be reached with a valid installer access key.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @return void
     */
    public static function assertIsAllowed(ServerRequestInterface $request): void
    {
        if (self::isAuthorized($request)) {
            return;
        }

        if (!self::isAccessKeyConfigured()) {
            throw new ForbiddenException(__(self::DISABLED_ERROR_MESSAGE));
        }

        throw new ForbiddenException(__(self::INVALID_ACCESS_KEY_ERROR_MESSAGE));
    }

    /**
     * Attempt to authorize the current session using the installer access key.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @return bool
     */
    public static function authorize(ServerRequestInterface $request): bool
    {
        $configuredAccessKey = self::getConfiguredAccessKey();
        if ($configuredAccessKey === null) {
            return false;
        }

        $providedAccessKey = self::getProvidedAccessKey($request);
        if ($providedAccessKey === null || !hash_equals($configuredAccessKey, $providedAccessKey)) {
            return false;
        }

        self::persistAuthorization($request, $configuredAccessKey);

        return true;
    }

    /**
     * Check whether the request session is currently authorized against the configured key.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @return bool
     */
    public static function isAuthorized(ServerRequestInterface $request): bool
    {
        $configuredAccessKey = self::getConfiguredAccessKey();
        if ($configuredAccessKey === null || !$request instanceof ServerRequest) {
            return false;
        }

        $authorizedFingerprint = $request->getSession()->read(self::ACCESS_AUTHORIZED_SESSION_KEY);
        if (!is_string($authorizedFingerprint) || $authorizedFingerprint === '') {
            return false;
        }

        return hash_equals(self::authorizationFingerprint($configuredAccessKey), $authorizedFingerprint);
    }

    /**
     * Check whether an installer access key is configured.
     *
     * @return bool
     */
    public static function isAccessKeyConfigured(): bool
    {
        return self::getConfiguredAccessKey() !== null;
    }

    /**
     * Return the access-key field name expected by the installer form.
     *
     * @return string
     */
    public static function getAccessKeyFieldName(): string
    {
        return self::ACCESS_KEY_FIELD;
    }

    /**
     * @return string
     */
    public static function getDisabledErrorMessage(): string
    {
        return __(self::DISABLED_ERROR_MESSAGE);
    }

    /**
     * @return string
     */
    public static function getInvalidAccessKeyErrorMessage(): string
    {
        return __(self::INVALID_ACCESS_KEY_ERROR_MESSAGE);
    }

    /**
     * @param string $accessKey The configured access key.
     * @return string
     */
    public static function authorizationFingerprint(string $accessKey): string
    {
        return hash('sha256', $accessKey);
    }

    /**
     * @return string|null
     */
    private static function getConfiguredAccessKey(): ?string
    {
        $configuredAccessKey = Configure::read(self::ACCESS_KEY_CONFIG);
        if (!is_string($configuredAccessKey) || $configuredAccessKey === '') {
            return null;
        }

        return $configuredAccessKey;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @return string|null
     */
    private static function getProvidedAccessKey(ServerRequestInterface $request): ?string
    {
        $providedAccessKey = $request->getHeaderLine(self::ACCESS_KEY_HEADER);
        if ($providedAccessKey !== '') {
            return $providedAccessKey;
        }

        if ($request instanceof ServerRequest) {
            $providedAccessKey = $request->getData(self::ACCESS_KEY_FIELD);
        } else {
            $parsedBody = $request->getParsedBody();
            $providedAccessKey = is_array($parsedBody) ? ($parsedBody[self::ACCESS_KEY_FIELD] ?? null) : null;
        }

        return is_string($providedAccessKey) && $providedAccessKey !== '' ? $providedAccessKey : null;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The current request.
     * @param string $configuredAccessKey The configured access key.
     * @return void
     */
    private static function persistAuthorization(ServerRequestInterface $request, string $configuredAccessKey): void
    {
        if (!$request instanceof ServerRequest) {
            return;
        }

        $session = $request->getSession();
        $session->renew();
        $session->write(
            self::ACCESS_AUTHORIZED_SESSION_KEY,
            self::authorizationFingerprint($configuredAccessKey),
        );
    }
}
