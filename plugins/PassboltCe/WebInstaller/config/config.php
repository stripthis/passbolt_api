<?php
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
 * @since         2.0.0
 */
return [
    'passbolt' => [
        'plugins' => [
            'webInstaller' => [
                'version' => '2.0.0',
            ],
        ],
        'webInstaller' => [
            'accessKey' => env('PASSBOLT_WEB_INSTALLER_ACCESS_KEY', null),
            'rateLimit' => [
                'maxAttempts' => filter_var(env('PASSBOLT_WEB_INSTALLER_RATE_LIMIT_MAX_ATTEMPTS', '5'), FILTER_VALIDATE_INT),
                'ipMaxAttempts' => filter_var(env('PASSBOLT_WEB_INSTALLER_RATE_LIMIT_IP_MAX_ATTEMPTS', '20'), FILTER_VALIDATE_INT),
                'cooldown' => filter_var(env('PASSBOLT_WEB_INSTALLER_RATE_LIMIT_COOLDOWN', '300'), FILTER_VALIDATE_INT),
            ],
        ],
    ],
];
