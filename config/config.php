<?php
/**
 * @copyright Ilch 2
 * @package ilch
 */

namespace Modules\Wgquicklogin\Config;

class Config extends \Ilch\Config\Install
{
    public $config = [
        'key' => 'wgquicklogin',
        'icon_small' => 'fa-sign-in',
        'author' => 'MonkeyOnKeyboard',
        'hide_menu' => true,
        'version' => '1.0.0',
        'languages' => [
            'de_DE' => [
                'name' => 'Anmelden mit WG Quicklogin',
                'description' => 'Erm&ouml;glicht Benutzern die Anmeldung per WG Quicklogin.',
            ],
            'en_EN' => [
                'name' => 'Sign in with QG Quicklogin',
                'description' => 'Allows users to sign in through WG Quicklogin.',
            ],
        ],
        'ilchCore' => '2.1.41',
        'phpVersion' => '7.0'
    ];

    public function install()
    {
        if (! $this->providerExists()) {
            $this->db()
                ->insert('auth_providers')
                ->values([
                    'key' => 'wgquicklogin_wg',
                    'name' => 'WGQuicklogin',
                    'icon' => 'fa-sign-in'
                ])
                ->execute();
        }

       $this->db()->query('
            CREATE TABLE IF NOT EXISTS `[prefix]_wgquicklogin_log` (
              `id` int(32) unsigned NOT NULL AUTO_INCREMENT,
              `type` varchar(50) DEFAULT \'info\',
              `message` text,
              `data` text,
              `created_at` DATETIME NOT NULL,
              PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        ');

        $this->db()
            ->insert('auth_providers_modules')
            ->values([
                'module' => 'wgquicklogin',
                'provider' => 'wgquicklogin_wg',
                'auth_controller' => 'auth',
                'auth_action' => 'index',
                'unlink_controller' => 'auth',
                'unlink_action' => 'unlink',
            ])
            ->execute();

    }

    public function uninstall()
    {
        $this->db()
            ->delete()
            ->from('auth_providers_modules')
            ->where(['module' => 'wgquicklogin'])
            ->execute();

        $this->db()
            ->delete()
            ->from('auth_providers')
            ->where(['key' => 'wgquicklogin_wg'])
            ->execute();

            $this->db()->queryMulti("
                DROP TABLE IF EXISTS `[prefix]_wgquicklogin_log`;
            ");
    }

    public function getUpdate($installedVersion)
    {
        switch ($installedVersion) {
            case "1.0.0":
                //
        }
    }

    /**
     * @return boolean
     */
    private function providerExists()
    {
        return (bool) $this->db()
            ->select('key')
            ->from('auth_providers')
            ->where(['key' => 'wgquicklogin_wg'])
            ->useFoundRows()
            ->execute()
            ->getFoundRows();
    }
}