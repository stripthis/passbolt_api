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
 * @since         2.0.0
 */
namespace Passbolt\WebInstaller\Controller;

use Cake\Controller\Controller;
use Cake\Http\Response;
use Cake\Routing\Router;
use Passbolt\WebInstaller\Service\WebInstallerAccessKeyRateLimiterService;
use Passbolt\WebInstaller\Utility\WebInstallerAccess;

class GettingStartedController extends Controller
{
    private const RATE_LIMITED_ERROR_MESSAGE = 'Too many invalid installer access key attempts. Please try again later.';

    /**
     * @inheritDoc
     */
    public function initialize(): void
    {
        parent::initialize();
        $this->loadComponent('Flash');
    }

    /**
     * Getting started with passbolt.
     * Is displayed instead of any other page if passbolt is not configured.
     *
     * @param \Passbolt\WebInstaller\Service\WebInstallerAccessKeyRateLimiterService $rateLimiter Rate limiter.
     * @return \Cake\Http\Response|null
     */
    public function index(WebInstallerAccessKeyRateLimiterService $rateLimiter): ?Response
    {
        if ($this->request->is('post')) {
            if (!WebInstallerAccess::isAccessKeyConfigured()) {
                $this->Flash->error(WebInstallerAccess::getDisabledErrorMessage());
            } elseif ($rateLimiter->isLimited($this->request)) {
                $this->Flash->error(__(self::RATE_LIMITED_ERROR_MESSAGE));
                $this->setResponse($this->response->withStatus(429));
            } elseif (WebInstallerAccess::authorize($this->request)) {
                $rateLimiter->clear($this->request);

                return $this->redirect(Router::url('/install/system_check', true));
            } else {
                $isLimited = $rateLimiter->recordFailure($this->request);
                if ($isLimited) {
                    $this->Flash->error(__(self::RATE_LIMITED_ERROR_MESSAGE));
                    $this->setResponse($this->response->withStatus(429));
                } else {
                    $this->Flash->error(WebInstallerAccess::getInvalidAccessKeyErrorMessage());
                }
            }
        }

        $this->set('accessKeyConfigured', WebInstallerAccess::isAccessKeyConfigured());
        $this->set('installerAuthorized', WebInstallerAccess::isAuthorized($this->request));
        $this->set('installerAccessKeyFieldName', WebInstallerAccess::getAccessKeyFieldName());
        $this->set('installerDisabledMessage', WebInstallerAccess::getDisabledErrorMessage());
        $this->render('Pages/getting_started');

        return null;
    }
}
