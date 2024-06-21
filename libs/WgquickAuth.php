<?php
namespace Modules\Wgquicklogin\Libs;

use Ilch\Request;
use Modules\Wgquicklogin\Mappers\DbLog;

/**
 * WgquickAuth Class
 *
 * @package   WgquickAuth
 * @author    Vikas Kapadiya <vikas@kapadiya.net>
 * @author    BlackCetha
 * @license   https://opensource.org/licenses/MIT The MIT License
 * @link      https://github.com/vikas5914/steam-auth
 * @version   1.0.0
 */

class WgquickAuth
{
    
    /**
     * Url OpenID EU
     */
    const OPEN_ID_URL = 'https://eu.wargaming.net/id/openid/';
    
    CONST REGION = 'eu';
    
    /**
     * Illuminate request class.
     *
     * @var Request
     */
    protected $request;
    
        
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
     *
     */
    
      
    
    public function __construct(
        $callbackUrl = null
        ) {
            
            $this->setCallbackUrl($callbackUrl);
            $this->region = self::REGION;
            $this->dbLog = new DbLog();
            $this->generateTimestamp();
    }
    
    /**
     * Returns a timestamp
     *
     * @see https://dev.wargaming.com/oauth/overview/authorizing-requests
     *
     * @return void
     */
    protected function generateTimestamp(){
        $this->setTimestamp(time()+60);
    }
    
        
    /**
     * @return string
     */
    public function getTimestamp(){
        return $this->timestamp;
    }
    
    /**
     * @param string $timestamp
     */
    public function setTimestamp($timestamp){
        $this->timestamp = $timestamp;
    }
    
        
    /**
     * @return string
     */
    public function getCallbackUrl(){
        return $this->callbackUrl;
    }
    
    /**
     * @param string $callbackUrl
     */
    public function setCallbackUrl($callbackUrl){
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
                
        $response = request('POST', $this->getOpenIdUrl(), [
            'form_params' => $this->getOpenIdValidationParams(),
        ]);
        
        $content = $response->getBody()->getContents();
        
        return strpos($content, 'is_valid:true') !== false;
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
     */
    public function debug()
    {
        echo "<h1>WgquickAuth debug report</h1><hr><b>Settings-array:</b><br>";
        echo "<pre>" . print_r($this->settings, true) . "</pre>";
        echo "<br><br><b>Data:</b><br>";
        echo "<pre>" . print_r($_SESSION["wgquicklogin"], true) . "</pre>";
    }
    
       
}
