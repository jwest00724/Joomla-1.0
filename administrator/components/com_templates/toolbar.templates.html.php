<?php
/**
* @version $Id$
* @package Joomla
* @subpackage Templates
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

/**
* @package Joomla
* @subpackage Templates
*/
class TOOLBAR_templates {
	public static function _DEFAULT($client) {
		mosMenuBar::startTable();
		if ($client=="admin") {
			mosMenuBar::custom('publish', 'publish.png', 'publish_f2.png', 'Default', true);
			mosMenuBar::spacer();
		} else {
			mosMenuBar::makeDefault();
			mosMenuBar::spacer();
			mosMenuBar::assign();
			mosMenuBar::spacer();
		}
		mosMenuBar::deleteList();
		mosMenuBar::spacer();
		mosMenuBar::editHtmlX( 'edit_source' );
		mosMenuBar::spacer();
		mosMenuBar::editCssX( 'edit_css' );
		mosMenuBar::spacer();
		mosMenuBar::addNew();
		mosMenuBar::spacer();
		mosMenuBar::help( 'screen.templates' );
		mosMenuBar::endTable();
	}
	public static function _VIEW(){
		mosMenuBar::startTable();
		mosMenuBar::back();
		mosMenuBar::endTable();
	}

	public static function _EDIT_SOURCE(){
		mosMenuBar::startTable();
		mosMenuBar::save( 'save_source' );
		mosMenuBar::spacer();
		mosMenuBar::cancel();
		mosMenuBar::endTable();
	}

	public static function _EDIT_CSS(){
		mosMenuBar::startTable();
		mosMenuBar::save( 'save_css' );
		mosMenuBar::spacer();
		mosMenuBar::cancel();
		mosMenuBar::endTable();
	}

	public static function _ASSIGN(){
		mosMenuBar::startTable();
		mosMenuBar::save( 'save_assign', 'Save' );
		mosMenuBar::spacer();
		mosMenuBar::cancel();
		mosMenuBar::spacer();
		mosMenuBar::help( 'screen.templates.assign' );
		mosMenuBar::endTable();
	}

	public static function _POSITIONS(){
		mosMenuBar::startTable();
		mosMenuBar::save( 'save_positions' );
		mosMenuBar::spacer();
		mosMenuBar::cancel();
		mosMenuBar::spacer();
		mosMenuBar::help( 'screen.templates.modules' );
		mosMenuBar::endTable();
	}
}
