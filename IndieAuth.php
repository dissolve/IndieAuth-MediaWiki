<?php

// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 2 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Copyright 2012 Aaron Parecki

error_reporting(E_ALL);

include('/web/include/NerdhausBot.inc.php');

//Extension credits that show up on Special:Version
$wgExtensionCredits['other'][] = array(
        'name' => 'IndieAuthPlugin',
        'version' => '0.1.0',
        'author' => array('Aaron Parecki'),
        'url' => 'https://github.com/aaronpk/IndieAuth-MediaWiki',
        'description' => 'Sign users in using IndieAuth',
);
 

$blacklist = array(
	'github.io',
	'wordpress.com',
	'blogspot.com',
	'livejournal.com'
);

// Override the login form with our own
$wgHooks['UserLoginForm'][] = 'IndieAuthPlugin::loginForm';

// Prevent creating accounts
$wgGroupPermissions['*']['createaccount'] = false;

// The Auth_remoteuser class is an AuthPlugin so make sure we have this included.
require_once('AuthPlugin.php');

// Set up the special page for handling the callback
$wgSpecialPages['IndieAuth'] = 'mwSpecialIndieAuth';



class mwSpecialIndieAuth extends SpecialPage
{
  function __construct()
  {
    SpecialPage::SpecialPage('IndieAuth');
  }
  
  function execute()
  {
    global $wgOut, $wgAction, $wgRequest, $wgSecureLogin, $blacklist;

    $wgOut->setPageTitle('IndieAuth');

    if(isset($_GET['code']))
    {
      $domain = IndieAuthPlugin::indieAuthDomainFromToken($_GET['code']);
      $username = IndieAuthPlugin::getCanonicalName($domain);

      // Check for logins from subdomains, not real indieweb domains
      foreach($blacklist as $b) {
	      if(strpos($domain, $b) !== FALSE) {
		      header('Location: http'.($wgSecureLogin ? 's' : '').'://' . $_SERVER['SERVER_NAME'] . '/Special:IndieAuth?error=subdomain');
		      die();
	      }
      }

      if($domain) {
        $id = User::idFromName($username);
        
        // If no user was found with their domain name as the username, check the OpenID table for the URL as well
    		$db = wfGetDB(DB_SLAVE);
    		$res = $db->select('user_openid', 
    			array('uoi_user'),
    			'uoi_openid LIKE "' . $domain . '%"',
    			__METHOD__,
    			array());
    		
    		$openIDUser = FALSE;
    		foreach($res as $row) { // there should be only one
    		  $openIDUser = $row->uoi_user;
    		}
    		if($openIDUser) {
    		  // If an existing user account was found, update the user record
    		  $user = User::newFromId($openIDUser);
    		  $user->loadFromId();
    		  $user->setRealName($domain);
    		  $user->mName = $username;
    		  $user->saveSettings();
    		  $id = $openIDUser;
    		}
        
        if (!$id) {
            $user = User::newFromName($username);
            $user->setRealName($domain);
            /* No account with this name found, so create one */
            $user->addToDatabase();
            #$user->setPassword(User::randomPassword());
            $user->setToken();
        } else {
            $user = User::newFromId($id);
            $user->loadFromId();
        }

        $user->setCookies();
        $user->saveSettings();

        if(class_exists('NerdhausBot')) {
          $N = new NerdhausBot('aaronpk');
          $N->Send('[mediawiki] ' . $domain . ' logged in via IndieAuth');
        }
      }

      if($_GET['returnto']) {
        $mReturnTo = $_GET['returnto'];
        $mReturnToQuery = @$_GET['returntoquery'];
        $titleObj = Title::newFromText( $mReturnTo );
        if ( !$titleObj instanceof Title ) {
          $titleObj = Title::newMainPage();
        }
        $redirectUrl = $titleObj->getFullURL( $mReturnToQuery );
        $wgOut->redirect( $redirectUrl );
      } else {
        header('Location: /');
      }
    }
    else
    {
      $errors = array(
        'subdomain' => 'You need to be hosting your identity from your own domain name, not from a shared domain. See <a href="http://indiewebcamp.com/Getting_Started">Getting Started</a> for more information.'
      );
      if(@$_GET['error']) {
	      $wgOut->addHTML('<p>' . $errors[$_GET['error']] . '</p>');
      }
      $wgOut->addHTML('<a href="http'.($wgSecureLogin ? 's' : '').'://' . $_SERVER['SERVER_NAME'] . '/Special:UserLogin">Log In</a>');
    }
  }
}


class IndieAuthPlugin extends AuthPlugin {

  public static function loginForm(&$template) {
    // Replace the default login form with our own
    $data = $template->data;
    $template = new IndieAuthLoginTemplate();
    $template->data = $data;
    return TRUE;
  }

  /**
   * Check whether there exists a user account with the given name.
   * The name will be normalized to MediaWiki's requirements, so
   * you might need to munge it (for instance, for lowercase initial
   * letters).
   *
   * @param string $username
   * @return bool
   * @access public
   */
  function userExists( $username ) {
    return true;
  }

  /**
   * NOTE: This is no longer used since the login form directs the user straight to indieauth.com, skipping the initial MW step 
   *
   * Check if a username+password pair is a valid login.
   * The name will be normalized to MediaWiki's requirements, so
   * you might need to munge it (for instance, for lowercase initial
   * letters).
   *
   * @param string $username
   * @param string $password
   * @return bool
   * @access public
   */
   
    function authenticate($username, $password) {
      global $wgSecureLogin;
      if(strtolower($username) == 'post-by-email' && $password == 'indieweb') return true;
      
      $titleObj = Title::newFromText('Special:IndieAuth');

      $redirect_uri = $titleObj->getFullURL(array_key_exists('returnto', $_GET) ? 'returnto='.$_GET['returnto'] : FALSE);
      $client_id = 'http'.($wgSecureLogin ? 's' : '').'://' . $_SERVER['SERVER_NAME'];

      header('Location: https://indieauth.com/auth?me=' . strtolower($username) . '&redirect_uri=' . urlencode($redirect_uri) . '&client_id=' . urlencode($client_id));
      die();
    }
  

  /**
   * Modify options in the login template.
   *
   * @param UserLoginTemplate $template
   * @access public
   */
  function modifyUITemplate( &$template, &$type ) {
    $template->set('usedomain', false );
    $template->set('useemail', false);      // Disable the mail new password box.
    $template->set('create', false);        // Remove option to create new accounts from the wiki.
  }

  /**
   * Check to see if the specific domain is a valid domain.
   *
   * @param string $domain
   * @return bool
   * @access public
   */
  function validDomain( $domain ) {
    # We ignore domains, so erm, yes?
    return true;
  }

  /**
   * When a user logs in, optionally fill in preferences and such.
   * For instance, you might pull the email address or real name from the
   * external user database.
   *
   * The User object is passed by reference so it can be modified; don't
   * forget the & on your function declaration.
   *
   * @param User $user
   * @access public
   */
  function updateUser( &$user ) {
    return;
  }

  /**
   * Return true if the wiki should create a new local account automatically
   * when asked to login a user who doesn't exist locally but does in the
   * external auth database.
   *
   * If you don't automatically create accounts, you must still create
   * accounts in some way. It's not possible to authenticate without
   * a local account.
   *
   * This is just a question, and shouldn't perform any actions.
   *
   * @return bool
   * @access public
   */
  function autoCreate() {
          return true;
  }


  /**
   * Can users change their passwords?
   *
   * @return bool
   */
  function allowPasswordChange() {
          # We can't change users system passwords
          return false;
  }

  /**
   * Set the given password in the authentication database.
   * Return true if successful.
   *
   * @param string $password
   * @return bool
   * @access public
   */
  function setPassword( $user, $password ) {
          # We can't change users system passwords
          return false;
  }

  /**
   * Update user information in the external authentication database.
   * Return true if successful.
   *
   * @param User $user
   * @return bool
   * @access public
   */
  function updateExternalDB( $user ) {
          # We can't change users details
          return false;
  }

  /**
   * Check to see if external accounts can be created.
   * Return true if external accounts can be created.
   * @return bool
   * @access public
   */
  function canCreateAccounts() {
          # We can't create accounts
          return false;
  }

  /**
   * Add a user to the external authentication database.
   * Return true if successful.
   *
   * @param User $user
   * @param string $password
   * @return bool
   * @access public
   */
  function addUser( $user, $password, $email='', $realname='' ) {
          # We can't create accounts
          return false;
  }


  /**
   * Return true to prevent logins that don't authenticate here from being
   * checked against the local database's password fields.
   *
   * This is just a question, and shouldn't perform any actions.
   *
   * @return bool
   * @access public
   */
  function strict() {
          # Only allow authentication from system database
          return true;
  }

  /**
   * When creating a user account, optionally fill in preferences and such.
   * For instance, you might pull the email address or real name from the
   * external user database.
   *
   * The User object is passed by reference so it can be modified; don't
   * forget the & on your function declaration.
   *
   * @param User $user
   * @access public
   */
  function initUser(&$user, $autocreate=false) {
          # We do everything in updateUser
  }

 
  /**
   * Normalize user names to the MediaWiki standard to prevent duplicate
   * accounts.
   *
   * @param $username String: username.
   * @return string
   * @public
   */
  function getCanonicalName($username) {
    // lowercase the username
    $username = strtolower($username);
    // remove the 'http' or 'https' on front
    $username = preg_replace('|^https?://|', '', $username);
    // remove trailing slash
    $username = trim($username, '/');
    // replace / with _
    $username = str_replace('/', '_', $username);
    $username = ucfirst($username);
    return $username;
  }

  function indieAuthDomainFromToken($token) {
    $ch = curl_init('https://indieauth.com/session?token=' . $token);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    $response = curl_exec($ch);
    if(!$response) {
      // error
      return FALSE;
    }
    $data = json_decode($response);
    if(!$data) {
      // error
      return FALSE;
    }
    if(!property_exists($data, 'me')) {
      // error
      return FALSE;
    }
    return $data->me;
  }
   
}
 
 


class IndieAuthLoginTemplate extends QuickTemplate {
  function execute() {
    global $wgSecureLogin;
    if( @$this->data['message'] ) {
?>
  <div class="<?php $this->text('messagetype') ?>box">
    <?php if ( $this->data['messagetype'] == 'error' ) { ?>
      <strong><?php $this->msg( 'loginerror' )?></strong><br />
    <?php } ?>
    <?php $this->html('message') ?>
  </div>
  <div class="visualClear"></div>
<?php } ?>

<div id="loginstart"><?php $this->msgWiki( 'loginstart' ); ?></div>
<div id="userloginForm">
<form name="userlogin" method="get" action="https://indieauth.com/auth">
  <h2><?php $this->msg('login') ?></h2>
  <p id="userloginlink"><?php $this->html('link') ?></p>
  <?php $this->html('header'); /* pre-table point for form plugins... */ ?>
  <!-- <div id="userloginprompt"><?php  $this->msgWiki('loginprompt') ?></div> -->
  <h4>Sign in with your domain</h4>
  <?php if( @$this->haveData( 'languages' ) ) { ?><div id="languagelinks"><p><?php $this->html( 'languages' ); ?></p></div><?php } ?>
  <table>
    <tr>
      <td class="mw-label"><label for='wpName1'>Your Domain</label></td>
      <td class="mw-input">
      	<input class="loginText" name="me" id="me" size="20" tabindex="1">
      </td>
    </tr>
    <tr>
      <td></td>
      <td class="mw-submit">
      	<input type="submit" value="Log In">
      </td>
    </tr>
  </table>
  <div id="userloginprompt" style="margin-top: 20px;">
    This is an <a href="https://indieauth.com/">IndieAuth</a> login prompt. To use it, you'll need to:
    <ul>
      <li>Add a link on your home page to your various social profiles (Twitter, Github, etc) with the attribute rel="me"</li>
      <li>Ensure your profiles link back to your home page.</li>
    </ul>
    Read the <a href="http://indiewebcamp.com/How_to_set_up_web_sign-in_on_your_own_domain">full setup instructions</a>.
  </div>

  <input type="hidden" name="redirect_uri" value="http<?= $wgSecureLogin ? 's' : '' ?>://<?= $_SERVER['SERVER_NAME'] ?>/Special:IndieAuth?returnto=<?= (array_key_exists('returnto', $_GET) ? $_GET['returnto'] : '')?>">
  <input type="hidden" name="client_id" value="http<?= $wgSecureLogin ? 's' : '' ?>://<?= $_SERVER['SERVER_NAME'] ?>">

  <script>
  	document.addEventListener("DOMContentLoaded", function(){
	  document.getElementById("me").focus();
  	});
  </script>
</form>
</div>
<div id="loginend"><?php $this->msgWiki( 'loginend' ); ?></div>
<?php

  }
}


