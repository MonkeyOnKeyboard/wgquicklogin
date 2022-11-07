<?php

namespace Modules\Wgquicklogin\Controllers\Admin;

use Ilch\Controller\Admin;

class Base extends Admin {
    /**
     * Init function
     */
    public function init()
    {
        $items = [
            [
                'name' => 'wgquicklogin.menu.logs',
                'active' => $this->isActive('index', 'index'),
                'icon' => 'fas fa-list',
                'url' => $this->getLayout()->getUrl(['controller' => 'index', 'action' => 'index'])
            ]
        ];

        $this->getLayout()->addMenu(
            'wgquicklogin.menu.signinwithapi',
            $items
        );
    }

    /**
     * Checks if the menu item is active
     *
     * @param $controller
     * @param $action
     *
     * @return bool
     */
    protected function isActive($controller, $action)
    {
        return $this->getRequest()->getControllerName() === $controller && $this->getRequest()->getActionName() === $action;
    }
}
