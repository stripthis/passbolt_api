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
 * @since         2.5.0
 */
namespace Passbolt\WebInstaller\Test\TestCase\Middleware;

use Cake\Core\Configure;
use Passbolt\WebInstaller\Test\Lib\WebInstallerIntegrationTestCase;
use Passbolt\WebInstaller\Utility\WebInstallerAccess;

class WebInstallerMiddlewareTest extends WebInstallerIntegrationTestCase
{
    public function testWebInstallerMiddleware_testConfiguredRedirect()
    {
        $backUpConfigured = Configure::read('passbolt.webInstaller.configured');
        Configure::write('passbolt.webInstaller.configured', true);
        $this->get('/users');
        $this->assertResponseCode(302);
        $this->assertRedirectContains('/auth/login');
        Configure::write('passbolt.webInstaller.configured', $backUpConfigured);
    }

    public function testWebInstallerMiddleware_testConfiguredForbidden()
    {
        $backUpConfigured = Configure::read('passbolt.webInstaller.configured');
        Configure::write('passbolt.webInstaller.configured', true);
        // We load the plugin here manually in order to ensure the routes to be defined.
        $this->loadPlugins(['Passbolt/WebInstaller' => ['bootstrap' => true, 'routes' => true]]);
        $this->get('/install');
        $this->assertResponseCode(403);
        Configure::write('passbolt.webInstaller.configured', $backUpConfigured);
    }

    public function testWebInstallerMiddleware_testMockNotConfiguredStartPage()
    {
        $this->mockPassboltIsNotconfigured();
        $this->get('/install');
        $data = $this->_getBodyAsString();
        $this->assertResponseOk();
        $this->assertStringContainsString('<div id="container" class="page setup start', $data);
    }

    public function testWebInstallerMiddleware_testAccessKeyAllowsInstallerStartPage()
    {
        $this->mockPassboltIsNotconfigured();
        $this->session(['webinstaller' => []]);

        $this->post('/install', ['installer_secret' => 'test-web-installer-secret']);

        $this->assertResponseCode(302);
        $this->assertRedirectContains('/install/system_check');
        $this->assertSession(
            WebInstallerAccess::authorizationFingerprint('test-web-installer-secret'),
            'webinstaller.accessAuthorized',
        );
    }

    public function testWebInstallerMiddleware_testInstallerDisabledWithoutAccessKey()
    {
        $this->mockPassboltIsNotconfigured();
        Configure::write('passbolt.webInstaller.accessKey', null);
        $this->session(['webinstaller' => []]);

        $this->get('/install');

        $this->assertResponseOk();
        $this->assertResponseContains('The web installer is disabled until an installer access key is configured.');
    }

    public function testWebInstallerMiddleware_testNotConfiguredInstallPageForbiddenForRemoteClients()
    {
        $this->mockPassboltIsNotconfigured();
        $this->mockUserIp('198.51.100.42');
        $this->session(['webinstaller' => []]);
        $this->get('/install/system_check');
        $this->assertResponseCode(403);
    }

    public function testWebInstallerMiddleware_testNotConfiguredInstallPageForbiddenForForwardedRemoteClients()
    {
        $this->mockPassboltIsNotconfigured();
        $this->session(['webinstaller' => []]);
        $this->configRequest([
            'environment' => ['HTTP_X_FORWARDED_FOR' => '198.51.100.42'],
        ]);
        $this->get('/install/system_check');
        $this->assertResponseCode(403);
    }

    public function testWebInstallerMiddleware_testRotatedAccessKeyInvalidatesAuthorizedSession()
    {
        $this->mockPassboltIsNotconfigured();
        Configure::write('passbolt.webInstaller.accessKey', 'rotated-web-installer-secret');

        $this->get('/install/system_check');

        $this->assertResponseCode(403);
    }

    public function testWebInstallerMiddleware_testInvalidAccessKeyAttemptsAreRateLimited()
    {
        $this->mockPassboltIsNotconfigured();
        $maxAttempts = Configure::read('passbolt.webInstaller.rateLimit.maxAttempts');
        $cooldown = Configure::read('passbolt.webInstaller.rateLimit.cooldown');
        Configure::write('passbolt.webInstaller.rateLimit.maxAttempts', 2);
        Configure::write('passbolt.webInstaller.rateLimit.cooldown', 300);
        $this->mockUserIp('198.51.100.99');
        $this->session(['webinstaller' => []]);

        $this->post('/install', ['installer_secret' => 'invalid-installer-secret']);
        $this->assertResponseOk();
        $this->_response = null;

        $this->post('/install', ['installer_secret' => 'invalid-installer-secret']);

        $this->assertResponseCode(429);
        $this->assertResponseContains('Too many invalid installer access key attempts. Please try again later.');
        Configure::write('passbolt.webInstaller.rateLimit.maxAttempts', $maxAttempts);
        Configure::write('passbolt.webInstaller.rateLimit.cooldown', $cooldown);
    }

    public function testWebInstallerMiddleware_testForwardedIpHeadersCannotBypassRateLimit()
    {
        $this->mockPassboltIsNotconfigured();
        $maxAttempts = Configure::read('passbolt.webInstaller.rateLimit.maxAttempts');
        $cooldown = Configure::read('passbolt.webInstaller.rateLimit.cooldown');
        Configure::write('passbolt.webInstaller.rateLimit.maxAttempts', 2);
        Configure::write('passbolt.webInstaller.rateLimit.cooldown', 300);
        $this->mockUserIp('198.51.100.100');
        $this->session(['webinstaller' => []]);
        $this->configRequest([
            'environment' => ['HTTP_X_FORWARDED_FOR' => '203.0.113.10'],
        ]);

        $this->post('/install', ['installer_secret' => 'invalid-installer-secret']);
        $this->assertResponseOk();
        $this->_response = null;

        $this->configRequest([
            'environment' => ['HTTP_X_FORWARDED_FOR' => '203.0.113.11'],
        ]);
        $this->post('/install', ['installer_secret' => 'invalid-installer-secret']);

        $this->assertResponseCode(429);
        $this->assertResponseContains('Too many invalid installer access key attempts. Please try again later.');
        Configure::write('passbolt.webInstaller.rateLimit.maxAttempts', $maxAttempts);
        Configure::write('passbolt.webInstaller.rateLimit.cooldown', $cooldown);
    }

    public function testWebInstallerMiddleware_testNotConfiguredRedirect()
    {
        $this->mockPassboltIsNotconfigured();
        $uris = ['/', 'auth/login', 'resources.json', 'users/recover'];
        foreach ($uris as $uri) {
            $this->get($uri);
            $this->assertResponseCode(302);
            $this->assertRedirectContains('/install');
            $this->_response = null; // Free the memory usage.
        }
    }
}
