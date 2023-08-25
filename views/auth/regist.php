<link href="<?=$this->getModuleUrl('static/css/steam.css') ?>" rel="stylesheet">

<form class="form-horizontal" method="POST" action="<?= $this->getUrl(['action' => 'save']) ?>" autocomplete="off">
    <legend><i class="fa-sign-in"></i><?=$this->getTrans('wgquicklogin.wgquicklogin') ?></legend>
    <div class="panel panel-default">
        <div class="bg-info panel-body">
            <?= $this->getTrans('wgquicklogin.passwordandemailneeded') ?>
        </div>
        <div class="panel-body">
            <?=$this->getTokenField() ?>
            <div class="form-group <?= ! $this->validation()->hasError('userName') ?: 'has-error' ?>">
                <label for="userNameInput" class="col-lg-3 control-label">
                    <?=$this->getTrans('wgquicklogin.username') ?>:
                </label>
                <div class="col-lg-9">
                    <input type="text"
                           class="form-control"
                           id="userNameInput"
                           name="userName"
                           value="<?= $this->originalInput('userName', $this->get('user')['screen_name']) ?>" />
                </div>
            </div>
            <div class="form-group <?= ! $this->validation()->hasError('email') ?: 'has-error' ?>">
                <label for="emailInput" class="col-lg-3 control-label">
                    <?=$this->getTrans('wgquicklogin.email') ?>:
                </label>
                <div class="col-lg-9">
                    <input type="email"
                           class="form-control"
                           id="emailInput"
                           name="email"
                           value="<?= $this->originalInput('email') ?>" />
                </div>
            </div>
        </div>
        <div class="panel-body">
            <?= $this->get('rules') ?>
        </div>
        <div class="bg-info panel-body">
            <?= $this->getTrans('wgquicklogin.rules') ?>
        </div>
        <div class="panel-footer">
            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-arrow-right"></i> <?= $this->getTrans('wgquicklogin.completeregistration') ?></button>
            <a href="#" class="btn btn-default"><?= $this->getTrans('wgquicklogin.cancel') ?></a>
        </div>
    </div>
</form>
