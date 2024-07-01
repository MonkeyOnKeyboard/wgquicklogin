<?php

/** @var $this \Ilch\View */

use Modules\wgquicklogin\Models\Log;
?>
<script>
    function syntaxHighlight(json) {
        if (typeof json != 'string') {
            json = JSON.stringify(json, undefined, 2);
        }
        json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            let cls = 'number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'key';
                } else {
                    cls = 'string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'boolean';
            } else if (/null/.test(match)) {
                cls = 'null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
    }
</script>
<style>
    div.log {
        display: flex;
        flex-wrap: nowrap;
    }

    div.log > .grow {
        flex-grow: 2;
        margin: 0 10px;
    }

    div.log > .type {
        flex-shrink: 1;
        text-transform: uppercase;
        font-weight: bold;
        align-self: flex-start;
    }

    pre.json .string { color: green; }
    pre.json .number { color: darkorange; }
    pre.json .boolean { color: blue; }
    pre.json .null { color: magenta; }
    pre.json .key { color: red; }

    div.log > .time {
        flex-shrink: 1;
        font-style: italic;
        color: #888888;
        align-self: flex-start;
        white-space: nowrap;
        margin-left: 10px;
    }

    div.log > .inspect {
        align-self: flex-start;
        flex-shrink: 1;
        margin-left: 10px;
    }

    .type.error {
        color: #FF0000;
    }
</style>

<h2><?= $this->getTrans('wgquicklogin.logs') ?></h2>

<div class="card card-default">
    <div class="card-heading clearfix">
        <i class="fa-solid fa-list"></i> <?= $this->getTrans('wgquicklogin.logmessages') ?>
        <form id="clearAll" action="<?= $this->getUrl(['action' => 'clear']) ?>" method="POST" class="pull-right">
            <?= $this->getTokenField() ?>

            <button type="submit" class="btn btn-danger btn-xs" onClick="event.preventDefault();
                if (confirm('<?= $this->getTrans('wgquicklogin.confirmclear') ?>')) {
                document.getElementById('clearAll').submit();
                }">
                <i class="fa-solid fa-trash-can"></i> <?= $this->getTrans('wgquicklogin.clearlogs') ?>
            </button>
        </form>
    </div>
    <!-- List group -->
    <ul class="list-group">
        <?php while($log = $this->get('logs')->fetchObject(Log::class, [])): ?>
            <?php /** @var $log Log */ ?>
            <li class="list-group-item">
                <div class="log">
                    <div class="type <?= $log->getType() ?>">
                        <?= $log->getType() ?>
                    </div>
                    <div class="time">
                        <?= $log->getLocalizedCreatedAt() ?>
                    </div>
                    <div class="grow">
                        <?= $log->getMessage() ?>
                    </div>
                    <?php if ($log->hasData()): ?>
                        <div class="inspect">
                            <button type="button" class="btn btn-primary btn-xs" data-toggle="modal" data-target="#inspectLogMessage-<?= $log->getId() ?>">
                                <i class="fa-solid fa-magnifying-glass"></i>
                            </button>
                        </div>
                    <?php endif; ?>
                    <div class="remove">
                        <form id="deleteLogMessage-<?= $log->getId() ?>" action="<?= $this->getUrl(['action' => 'delete', 'id' => $log->getId()]) ?>" method="POST" class="pull-right">
                            <?= $this->getTokenField() ?>

                            <button type="submit" class="btn btn-danger btn-xs" onClick="event.preventDefault();
                                if (confirm('<?= $this->getTrans('wgquicklogin.confirmdelete') ?>')) {
                                    document.getElementById('deleteLogMessage-<?= $log->getId() ?>').submit();
                                }">
                                <i class="fa-solid fa-trash-can"></i>
                            </button>
                        </form>
                    </div>
                </div>
            </li>
            <?php if ($log->hasData()): ?>
                <div class="modal fade" id="inspectLogMessage-<?= $log->getId() ?>" tabindex="-1" role="dialog" aria-labelledby="LogMessage">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-header">
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                                <h4 class="modal-title" id="myModalLabel"><?= $this->getTrans('wgquicklogin.inspectinglogmessage') ?></h4>
                            </div>
                            <div class="modal-body">
                                <pre class="json"><script>document.write(syntaxHighlight(JSON.stringify(JSON.parse('<?= $log->getData() ?>'), null, 2)))</script></pre>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-default" data-dismiss="modal"><?= $this->getTrans('wgquicklogin.close') ?></button>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        <?php endwhile; ?>
        <?php if ($this->get('logs')->getNumRows() === 0): ?>
            <li class="list-group-item"><?= $this->getTrans('wgquicklogin.nologsfound') ?></li>
        <?php endif; ?>
    </ul>
</div>
