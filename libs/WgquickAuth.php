<?php

namespace Modules\Wgquicklogin\Libs;

use Exception;

/**
 * WgquickAuth Class
 */

class WgquickAuth
{
    /**
     * Url OpenID EU
     */
    public const OPEN_ID_URL = 'https://eu.wargaming.net/id/openid/';

    public const REGION = 'eu';


    /**
     * Region.
     *
     * @var string
     */
    protected $region;

    /**
     * Realm
     *
     * @var string
     */
    protected $realm;


    /**
     * The callback url
     *
     * @var string
     */
    protected $callbackUrl;

    /**
     * The parameters
     *
     * @var array
     */
    protected $parameters;


    /**
     * The Auth url openid
     *
     * @var string
     */
    protected $authUrl;

    /**
     * The Token
     *
     * @var string
     */
    protected $token;


    /**
     * Creates new instance.
     * @param string|null $callbackUrl
     */
    public function __construct(
        ?string $callbackUrl = null
    ) {

        $this->setCallbackUrl($callbackUrl ?? '');
        $this->region = self::REGION;
    }


    /**
     * @return string
     */
    public function getCallbackUrl(): string
    {
        return $this->callbackUrl;
    }

    /**
     * @param string $callbackUrl
     */
    public function setCallbackUrl(string $callbackUrl)
    {
        $this->callbackUrl = $callbackUrl;
    }



    /**
     * Returns the region.
     *
     * @return string
     */
    public function getRegion(): string
    {
        return $this->region;
    }

    /**
     * Set the region.
     *
     * @param string $region
     */
    public function setRegion(string $region)
    {
        $this->region = $region;
    }

    /**
     * Returns the realm.
     *
     * @return string
     */
    public function getRealm(): string
    {
        return $this->realm;
    }

    /**
     * Set the realm.
     *
     * @param string $realm
     */
    public function setRealm(string $realm)
    {
        $this->realm = $realm;
    }

    /**
     * Returns the OpenID URL.
     *
     * @return string
     */
    public function getOpenIdUrl(): string
    {
        return 'https://' . $this->region . '.wargaming.net/id/openid/';
    }

    /**
     * Returns the redirect URL.
     *
     * @return string
     */
    public function redirectUrl(): string
    {
        $params = [
            'openid.ax.if_available' => 'ext0,ext1',
            'openid.ax.mode' => 'fetch_request',
            'openid.ax.type.ext0' => 'http://axschema.openid.wargaming.net/spa/id',
            'openid.ax.type.ext1' => 'http://axschema.org/namePerson/friendly',
            'openid.claimed_id' => 'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.identity' => 'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.mode' => 'checkid_setup',
            'openid.ns' => 'http://specs.openid.net/auth/2.0',
            'openid.ns.ax' => 'http://openid.net/srv/ax/1.0',
            'openid.return_to' => $this->getCallbackUrl(),
        ];

        return $this->getOpenIdUrl() . '?' . http_build_query($params, '', '&');
    }

    /**
     * OpenID Positive Assertions.
     *
     * @return bool
     */
    private function isPositiveAssertion(): bool
    {
        $hasFields = [
            'openid_assoc_handle' => $_GET['openid_assoc_handle'],
            'openid_claimed_id' => $_GET['openid_claimed_id'],
            'openid_identity' => $_GET['openid_identity'],
            'openid_mode' => $_GET['openid_mode'],
            'openid_ns' => $_GET['openid_ns'],
            'openid_op_endpoint' => $_GET['openid_op_endpoint'],
            'openid_response_nonce' => $_GET['openid_response_nonce'],
            'openid_return_to' => $_GET['openid_return_to'],
            'openid_sig' => $_GET['openid_sig'],
            'openid_signed' => $_GET['openid_signed'],
        ];

        $isModeIdRes = $_GET['openid_mode'] === 'id_res';

        return $hasFields && $isModeIdRes;
    }

    /**
     * OpenID Verifying the Return URL.
     *
     * @return bool
     */
    public function verifyingReturnUrl(): bool
    {
        return $_GET['openid_return_to'] === $this->getCallbackUrl();
    }

    /**
     * Get param list for OpenID validation
     *
     * @return array
     */
    private function getOpenIdValidationParams(): array
    {
        $params = [];
        $signedParams = explode(',', $_GET['openid_signed']);

        foreach ($signedParams as $item) {
            $params['openid.' . $item] = $_GET['openid_' . str_replace('.', '_', $item)];
        }

        $params['openid.mode'] = 'check_authentication';
        $params['openid.sig'] = $_GET['openid_sig'];

        return $params;
    }

    /**
     * OpenID Verifying Signatures (Wargaming uses Direct Verification).
     *
     * @return bool
     *
     */
    public function verifyingSignatures(): bool
    {
        $content = $this->sendRequest('POST', $this->getOpenIdUrl(), $this->getOpenIdValidationParams());

        return strpos($content, 'is_valid:true') !== false;
    }

    /**
     * @param string $method
     * @param string $url
     * @param array|null $data
     * @return bool|string
     */
    public function sendRequest(string $method, string $url, ?array $data = [])
    {
        $response = false;
        try {
            // Initialisieren einer cURL-Sitzung
            $ch = curl_init();

            // Konvertieren Sie das Datenarray in einen URL-kodierten Abfrage-String für GET-Anfragen
            if ($method == 'GET' && !empty($data)) {
                $queryString = http_build_query($data);
                $url .= '?' . $queryString;
            }

            // Setzen der cURL-Optionen
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
            ]);

            // Für POST-Anfragen
            if ($method == 'POST') {
                curl_setopt($ch, CURLOPT_POST, 1);
                if (!empty($data)) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
                }
            }

            // Ausführen der Anfrage und Abrufen der Antwort
            $response = curl_exec($ch);

            if (curl_errno($ch)) {
                throw new Exception(curl_error($ch));
            }
        } catch (Exception $e) {
            return false;
        } finally {
            if (is_resource($ch)) {
                curl_close($ch);
            }
        }
        return $response;
    }

    /**
     * Process to verify an OpenID assertion.
     *
     * @return bool
     *
     */
    public function verify(): bool
    {
        return $this->isPositiveAssertion()
            && $this->verifyingReturnUrl()
            && $this->verifyingSignatures();
    }

    /**
     * Returns the user data.
     *
     * @return array
     */
    public function user(): array
    {
        return [
            'id' => $_GET['openid_ax_value_ext0_1'],
            'nickname' => $_GET['openid_ax_value_ext1_1'],
            'token' => $_GET['openid_assoc_handle'],

        ];
    }

    /**
     * Prints debug information about wgquicklogin
     *
     * @param bool $print
     * @return string
     */
    public function debug(bool $print = true): string
    {
        $var = "<h1>WgquickAuth debug report</h1><hr>";
        $var .= "<br><br><b>Data:</b><br>";
        $var .= "<pre>" . print_r($_SESSION["wgquicklogin"], true) . "</pre>";

        if ($print) {
            echo $var;
        }
        return $var;
    }
}
