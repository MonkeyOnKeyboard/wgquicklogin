<?php

namespace Modules\Wgquicklogin\Controllers\Admin;

use Modules\Wgquicklogin\Mappers\DbLog;

class Index extends Base
{
    public function indexAction()
    {
        $this->getLayout()->getAdminHmenu()
            ->add($this->getTranslator()->trans('wgquicklogin.menu.signinwithapi'), ['controller' => 'index', 'action' => 'index'])
            ->add($this->getTranslator()->trans('wgquicklogin.menu.logs'), ['action' => 'index']);

        $dbLog = new DbLog();
        $this->getView()->set('logs', $dbLog->getAll());
    }

    public function clearAction()
    {
        if (! $this->getRequest()->isPost()) {
            $this->addMessage('wgquicklogin.methodnotallowed', 'danger');

            $this->redirect(['action' => 'index']);
        }

        $dbLog = new DbLog();

        try {
            $dbLog->clear();

            $this->addMessage('wgquicklogin.loghasbeencleared');

            $this->redirect(['action' => 'index']);
        } catch (\Exception $e) {
            $this->addMessage('wgquicklogin.couldnotclearlog', 'danger');

            $this->redirect(['action' => 'index']);
        }
    }

    public function deleteAction()
    {
        $dbLog = new DbLog();

        try {
            $dbLog->delete($this->getRequest()->getParam('id'));

            $this->addMessage('wgquicklogin.logdeletedsuccessful');

            $this->redirect(['action' => 'index']);
        } catch (\Exception $e) {
            $this->addMessage('wgquicklogin.logdeletederror', 'danger');

            $this->redirect(['action' => 'index']);
        }
    }
}
