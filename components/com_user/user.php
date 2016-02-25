<?php
/**
* @version $Id$
* @package Joomla
* @subpackage Users
* @copyright Copyright (C) 2005 Open Source Matters. All rights reserved.
* @license http://www.gnu.org/licenses/gpl-2.0.html GNU/GPL, see LICENSE.php
* Joomla! is free software. This version may have been modified pursuant
* to the GNU General Public License, and as distributed it includes or
* is derivative of works licensed under the GNU General Public License or
* other free or open source software licenses.
* See COPYRIGHT.php for copyright notices and details.
*/

// no direct access
defined( '_VALID_MOS' ) or die( 'Restricted access' );

// Editor usertype check
$access = new stdClass();
$access->canEdit = $acl->acl_check( 'action', 'edit', 'users', $my->usertype, 'content', 'all' );
$access->canEditOwn = $acl->acl_check( 'action', 'edit', 'users', $my->usertype, 'content', 'own' );

require_once ( $mainframe->getPath( 'front_html' ) );

switch( $task ) {
	case 'UserDetails':
		userEdit( $option, $my->id, _UPDATE );
		break;

	case 'saveUserEdit':
		// check to see if functionality restricted for use as demo site
		if ( $_VERSION->RESTRICT == 1 ) {
			mosRedirect( 'index.php?mosmsg=Functionality Restricted' );
		} else {
			userSave( $option, $my->id );
		}
		break;


	case 'cancel':
		mosRedirect( 'index.php' );
		break;

	default:
		HTML_user::frontpage();
		break;
}

function userEdit( $option, $uid, $submitvalue) {
	global $database, $mainframe;
	global $mosConfig_absolute_path;

	// security check to see if link exists in a menu
	$link = 'index.php?option=com_user&task=UserDetails';
	$query = "SELECT id"
	. "\n FROM #__menu"
	. "\n WHERE link LIKE '%$link%'"
	. "\n AND published = 1"
	;
	$database->setQuery( $query );
	$exists = $database->loadResult();
	if ( !$exists ) {
		mosNotAuth();
		return;
	}

	require_once( $mosConfig_absolute_path .'/administrator/components/com_users/users.class.php' );

	if ($uid == 0) {
		mosNotAuth();
		return;
	}
	$row = new mosUser( $database );
	$row->load( (int)$uid );
	$row->orig_password = $row->password;

	$row->name = trim( $row->name );
	$row->email = trim( $row->email );
	$row->username = trim( $row->username );

	$file 	= $mainframe->getPath( 'com_xml', 'com_users' );
	$params = new mosUserParameters( $row->params, $file, 'component' );

	HTML_user::userEdit( $row, $option, $submitvalue, $params );
}

function userSave( $option, $uid) {
	global $database, $my, $mosConfig_frontend_userparams;

	$user_id = intval( mosGetParam( $_POST, 'id', 0 ));

	// do some security checks
	if ($uid == 0 || $user_id == 0 || $user_id != $uid) {
		mosNotAuth();
		return;
	}

	// simple spoof check security
	josSpoofCheck();

	$row = new mosUser( $database );
	$row->load( (int)$user_id );

	$orig_password = $row->password;
	$orig_username = $row->username;

	if (!$row->bind( $_POST, 'gid usertype' )) {
		echo "<script> alert('".$row->getError()."'); window.history.go(-1); </script>\n";
		exit();
	}

	$row->name = trim($row->name);
	$row->email = trim($row->email);
	$row->username = trim($row->username);

	mosMakeHtmlSafe($row);

	if (isset($_POST['password']) && $_POST['password'] != '') {
		if (isset($_POST['verifyPass']) && ($_POST['verifyPass'] == $_POST['password'])) {
			$row->password = trim($row->password);
			$salt = mosMakePassword(16);
			$crypt = md5($row->password.$salt);
			$row->password = $crypt.':'.$salt;
		} else {
			echo "<script> alert(\"".addslashes( _PASS_MATCH )."\"); window.history.go(-1); </script>\n";
			exit();
		}
	} else {
		// Restore 'original password'
		$row->password = $orig_password;
	}

	if ($mosConfig_frontend_userparams == '1' || $mosConfig_frontend_userparams == 1 || $mosConfig_frontend_userparams == NULL) {
	// save params
		$params = mosGetParam( $_POST, 'params', '' );
		if (is_array( $params )) {
			$txt = array();
			foreach ( $params as $k=>$v) {
				$txt[] = "$k=$v";
			}
			$row->params = implode( "\n", $txt );
		}
	}

	if (!$row->check()) {
		echo "<script> alert('".$row->getError()."'); window.history.go(-1); </script>\n";
		exit();
	}

	if (!$row->store()) {
		echo "<script> alert('".$row->getError()."'); window.history.go(-1); </script>\n";
		exit();
	}

	// check if username has been changed
	if ( $orig_username != $row->username ) {
		// change username value in session table
		$query = "UPDATE #__session"
		. "\n SET username = " . $database->Quote($row->username)
		. "\n WHERE username = " . $database->Quote( $orig_username )
		. "\n AND userid = " . (int) $my->id
		. "\n AND gid = " . (int) $my->gid
		. "\n AND guest = 0"
		;
		$database->setQuery( $query );
		$database->query();
	}

	mosRedirect( 'index.php', _USER_DETAILS_SAVE );
}



