<?php

/**
 *   Automatic Detection of Information Leakage Vulnerabilities in
 *   Web Applications.
 *
 *   Copyright (C) 2015-2018 Ruhr University Bochum
 *
 *   @author Yakup Ates <Yakup.Ates@rub.de
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

include 'libs/analyser.php';

class Model{
    private $controller;
    private $source;
    private $analyser;
    private $DOM;

    private $cms;
    private $cms_found = FALSE;
    private $plugins;
    private $jslib;
    private $email;
    private $phone_numbers;
    private $dangerLevel;
    private $callbackurls;

    
    public function __construct($controller) {
        $this->controller = $controller;
        $this->source = $this->controller->getSource();

        if ($this->controller->getScannerHasError()) {
            return;
        }
        
        $this->dangerLevel = $this->controller->getDangerLevel();
        $this->callbackurls = $this->controller->getCallbackurls();

        $this->analyser = new Analyser($this->source);
        $this->DOM = $this->analyser->getDOM();

        $this->cms = $this->analyser->analyse_cms();
        /* CMS detected, search for its plugins */
        if (!empty($this->cms['cms'])) {
            $this->plugins = $this->analyser->analyse_plugins($this->cms['cms']);
        }
        
        $this->jslib = $this->analyser->analyse_JSLib();
        $this->email = $this->analyser->find_email($this->source);
        $this->phone_numbers = $this->analyser->find_phoneNumber($this->source);
    }

    /* @short: Returns source code of the target. */
    public function getSource() {
        return $this->source;
    }

    /* @short: Returns all nodes which hints the CMS used by the target.*/
    public function getCMS() {
        return $this->cms;
    }

    /* @short: Returns a list of used CMS plugins by the target. */
    public function getPlugin() {
        return $this->plugins;
    }

    /* @short: Returns all E-Mail addresses found in the DOM. */
    public function getEmail() {
        return $this->email;
    }

    /* @short: Returns all JavaScript libraries found in the DOM. */
    public function getJSLib() {
        return $this->jslib;
    }

    /* @short: Returns all phone numbers found in the DOM. */
    public function getPhoneNumbers() {
        return $this->phone_numbers;
    }

    /* @short: Return DOM */
    public function getDOM() {
        return $this->DOM;
    }
}

?>
