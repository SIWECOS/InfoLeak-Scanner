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

include __DIR__ . '/../01_model/libs/messages.php';

/**
 * Returns JSON output of findings.
 */
class View{
    private $model;
    private $controller;
    private $messages;
    private $mode;
    private $scan_count = 5;
    private $global_score = 0;

    public function __construct($model, $controller) {
    private $scan_result;

    private static $scoreType_enum = array(
        0 => "critical",
        1 => "warning",
        2 => "success",
        3 => "bonus",
        4 => "info",
        5 => "hidden"
    );

    public function scoreType($ordinal) {
        return self::$scoreType_enum[$ordinal];
    }

    public function __construct($model, $controller, $mode) {
        $this->model      = $model;
        $this->controller = $controller;
        $this->mode       = $mode;

        $this->messages   = new Messages();
        
        $this->printJSON($mode);
    }

    public function getScanResult() {
        return $this->scan_result;
    }
    
    private function printCMS() {
        $nodes    = $this->model->getCMS();

        $isVuln   = $nodes['isVuln'];
        $version  = $nodes['version'];
        $cms      = $nodes['cms'];
        $cms_node = $nodes['node'];
        $MAX_FINDING_OUT = 1;
        $result    = array();


        $result['name'] = "CMS";
        $result['hasError'] = FALSE;
        $result['errorMessage'] = NULL;
        $result['testDetails'] = array();
        $result['scoreType'] = $this->scoreType(4);

        if (!empty($cms)) {
            $result['score'] = 60; // TODO: higher/lower risk if version was detected etc

            if (!$version) {

                $result['testDetails'][0]['placeholder'] = "CMS_ONLY";
                $result['testDetails'][0]['values']['cms'] = $cms;
                //$result['comment'] = $this->messages->getMessageByName('CMS_ONLY',
                //                                                       $cms);
            } else {
                if ($isVuln) {
                    //$result['risk'] = 10;
                    $result['testDetails'][0]['placeholder'] = "CMS_VERSION_VULN";
                    $result['testDetails'][0]['values']['cms'] = $cms;
                    $result['testDetails'][0]['values']['VERSION'] = $version;

                    //$result['comment'] = $this->messages->getMessageByName('CMS_VERSION_VULN',
                    //                                                       $cms . " " . $version);
                } else {
                    //$result['risk'] = 8;
                    $result['testDetails'][0]['placeholder'] = "CMS_VERSION_VULN";
                    $result['testDetails'][0]['values']['cms'] = $cms;
                    $result['testDetails'][0]['values']['VERSION'] = $version;

                    //$result['comment'] = $this->messages->getMessageByName('CMS_VERSION',
                    //                                                       $cms . " " . $version);
                }
            }

            if ($cms_node->nodeName === "script") {
                //$result['finding'] = preg_replace("/\\n|\\t/", "",
                //                                  $cms_node->nextSibling->nodeValue);
                $result['testDetails'][0]['values']['node'] = $cms_node->nodeName;
                $result['testDetails'][0]['values']['node_content'] = $cms_node->nextSibling->nodeValue;

                if (strlen($result['finding']) > 100) {
                    $result['finding']  = substr($result['finding'], 0, 100);
                    $result['finding'] .= " [...]";
                }
            } else {
                $i = 0;

                foreach($cms_node->attributes as $attr) {
                    $finding = $attr->name . " : " . $attr->value;

                    if ($i < $MAX_FINDING_OUT)
                        $i++;
                    else
                        break;
                }

                if (strlen($finding) > 100) {
                    $finding  = substr($finding, 0, 100);
                    $finding .= " [...]";
                }

                //$result['finding'] = preg_replace("/\\n|\\t/", "",
                //                                 "[" . $cms_node->nodeName . "]"
                //                                  . ": " . $finding);
                $result['testDetails'][0]['values']['node'] = $cms_node->nodeName;
                $result['testDetails'][0]['values']['node_content'] = $finding;

            }
        } else {
            $result['score']      = 0;
            $result['testDetails'][0] = NULL;

            //$result['comment'] = $this->messages->getMessageByName('NO_CMS');
            //$result['finding'] = $this->messages->getMessageByName('NO_FINDING');
        }

        $this->global_score += $result['score'];
        $sorted_result = array("name"         => $result['name'],
                               "hasError"     => $result['hasError'],
                               "errorMessage" => $result['errorMessage'],
                               "score"        => $result['score'],
                               "scoreType"    => $result['scoreType'],
                               "testDetails"  => $result['testDetails']);

        return $sorted_result;
    }

    /**
     *
     */
    private function printPlugin() {
        $nodes = $this->model->getPlugin();

        $result  = array();

        $result['name']  = "CMS_PLUGINS";
        $result['hasError'] = FALSE;
        $result['errorMessage'] = NULL;
        $result['testDetails'] = array();
        $result['scoreType'] = $this->scoreType(1);

        if (count($nodes) > 1) {
            $isVuln   = $nodes['result'];
            $f_val    = $nodes['pVal'];
            $nodeName = $nodes['attrName'];
            $version  = $nodes['version'];
            $plugin_name = $nodes['plugin_name'];
            $result['score'] = 70; // TODO: higher/lower risk if version was detected etc

            $limit = 2;
            if (count($isVuln) < $limit)
                $limit = count($isVuln);


            for ($j=0; $j < $limit; $j++) {
                if ($isVuln[$j] === NULL)
                    break;

                if (strlen($f_val[$j]) > 100) {
                    $f_val[$j]  = substr($f_val[$j], 0, 100);
                    $f_val[$j] .= " [...]";
                }

                //$result['result'][] = $isVuln[$j];
                if ($isVuln[$j]) {
                    //$result['comment'][] = $comment[$j];
                    //$result['comment'][] = $this->messages->getMessageByName('PLUGIN_VERSION_VULN', $plugin_name[$j] . " " . $version[$j]);
                    $result['testDetails'][0]['placeholder'] = "PLUGIN_VERSION_VULN";
                    $result['testDetails'][0]['values']['plugin'] = $plugin_name[$j];
                    $result['testDetails'][0]['values']['plugin_version'] = $version[$j];
                    $result['testDetails'][0]['values']['node'] = $nodeName[$j];
                    $result['testDetails'][0]['values']['node_content'] = $f_val[$j];
                } else {
                    if ($version[$j] === NULL) {
                        $result['testDetails'][0]['placeholder'] = "PLUGIN_ONLY";
                        $result['testDetails'][0]['values']['plugin'] = $plugin_name[$j];
                        $result['testDetails'][0]['values']['node'] = $nodeName[$j];
                        $result['testDetails'][0]['values']['node_content'] = $f_val[$j];

                        //$result['comment'][] = $this->messages->getMessageByName('PLUGIN_ONLY', $plugin_name[$j]);
                        //$result['finding'][] = $f_val[$j];
                    } else {
                        $result['testDetails'][0]['placeholder'] = "PLUGIN_VERSION";
                        $result['testDetails'][0]['values']['plugin'] = $plugin_name[$j];
                        $result['testDetails'][0]['values']['plugin_version'] = $version[$j];
                        $result['testDetails'][0]['values']['node'] = $nodeName[$j];
                        $result['testDetails'][0]['values']['node_content'] = $f_val[$j];

                        //$result['comment'][] = $this->messages->getMessageByName('PLUGIN_ONLY', $plugin_name[$j] . " " . $version[$j]);
                        //$result['finding'][] = $f_val[$j];
                    }
                }
            }
        } else {
            $result['score'] = 0;

            $result['testDetails'][0] = NULL;
            $result['testDetails'][0] = NULL;

            //$result['comment'] = $this->messages->getMessageByName('NO_PLUGINS');
            //$result['finding'] = $this->messages->getMessageByName('NO_FINDING');
        }

        $this->global_score += $result['score'];        
        $sorted_result = array("name"         => $result['name'],
                               "hasError"     => $result['hasError'],
                               "errorMessage" => $result['errorMessage'],
                               "score"        => $result['score'],
                               "scoreType"    => $result['scoreType'],
                               "testDetails"  => $result['testDetails']);


        return $sorted_result;
    }

    /**
     *
     */
    private function printJS(){
        $nodes   = $this->model->getJSLib();
        $isVuln  = $nodes['isVuln'];
        $version = $nodes['version'];
        $lib     = $nodes['lib'];
        $nodes   = $nodes['nodes'];
        $result  = $finding = array();

        /* Print only 2 finding nodes. */
        $MAX_FINDING_OUT = 2;

        $result['name']  = "JS_LIB";
        $result['hasError'] = FALSE;
        $result['errorMessage'] = NULL;
        $result['testDetails'] = array();
        $result['scoreType'] = $this->scoreType(1);

        if (!empty($nodes)) {
            $i = $j = 0;
            $result['score']     = 50;

            $result['testDetails'][0]['placeholder'] = "JS_LIB_ONLY";
            $result['testDetails'][0]['values']['js_lib_name'] = $lib[$i];

            //$result['comment']  = $this->messages->getMessageByName('JS_ONLY',
            //                                                        $lib[$i]);

            foreach($nodes as $node) {
                if ($j < $MAX_FINDING_OUT)
                    $j++;
                else
                    break;

                foreach($node->attributes as $attribute) {
                    $finding['node_content'] = $attribute->value;
                    $finding['node_name'] = $attribute->name;

/*
                    if (strlen($finding['node_content']) > 100) {
                        $finding['node_content']  = substr($finding['node_content'], 0, 100);
                        $finding['attr'] .= " [...]";
                    }
*/
                }

                if ((!empty($version[$i])) &&
                    ($version[$i] !== "N/A")) {
                    //$result['risk'] = 6;

                    $result['testDetails'][0]['placeholder'] = "JS_LIB_VERSION";
                    $result['testDetails'][0]['values']['js_lib_name'] = $lib[$i];
                    $result['testDetails'][0]['values']['js_lib_version'] = $version[$i];

                    //$result['comment']   = $this->messages->getMessageByName('JS_VERSION',
                    //                                                         $lib[$i] . " " . $version[$i]);
                } else {
                    unset($result['version']);
                }

                if ((!empty($isVuln[$i])) &&
                    ($isVuln[$i] !== "N/A")) {
                    //$result['risk'] = 8;
                    //$result['result'] = $isVuln[$i];

                    $result['testDetails'][0]['placeholder'] = "JS_LIB_VULN_VERSION";
                    $result['testDetails'][0]['values']['js_lib_name'] = $lib[$i];
                    $result['testDetails'][0]['values']['js_lib_version'] = $version[$i];

                    //$result['comment']   = $this->messages->getMessageByName('JS_VULN_VERSION',
                    //                                                         $lib[$i] . " " . $version[$i]);
                }


                $i++;
                    $result['testDetails'][0]['values']['node'] = $finding['node_name'];
                $result['testDetails'][0]['values']['node_content'] = $finding['node_content'];
            }
        } else {
            $result['score'] = 0;

            $result['testDetails'][0] = NULL;
            $result['testDetails'][0] = NULL;

            //$result['comment'] = $this->messages->getMessageByName('NO_JS');
            //$result['finding'] = $this->messages->getMessageByName('NO_FINDING');
        }

        $this->global_score += $result['score'];        
        $sorted_result = array("name"         => $result['name'],
                               "hasError"     => $result['hasError'],
                               "errorMessage" => $result['errorMessage'],
                               "score"        => $result['score'],
                               "scoreType"    => $result['scoreType'],
                               "testDetails"  => $result['testDetails']);

        return $sorted_result;
    }


    /**
     *
     */
    private function printEmail() {
        $emails = $this->model->getEmail();
        $j = 0;

        $result['name']  = "EMAIL_ADDRESS";
        $result['hasError'] = FALSE;
        $result['errorMessage'] = NULL;
        $result['testDetails'] = array();
        $result['scoreType'] = $this->scoreType(4);

        if (!empty($emails)) {
            $result['score']   = 70;
            $result['testDetails'][0]['placeholder'] = "EMAIL_FOUND";

            $result['testDetails'][0]['values']['email_address'][] = $emails;
            //$emails_['comment'] = $this->messages->getMessageByName('EMAIL_ONLY');
        } else {
            $result['score'] = 0;

            $result['testDetails'][0] = NULL;
            $result['testDetails'][0] = NULL;

            //$emails_['score']   = 0;

            //  $emails_['comment'] = $this->messages->getMessageByName('NO_EMAIL');
            //  $emails_['finding'] = $this->messages->getMessageByName('NO_FINDING');
        }

        $this->global_score += $result['score'];
        $sorted_result = array("name"         => $result['name'],
                               "hasError"     => $result['hasError'],
                               "errorMessage" => $result['errorMessage'],
                               "score"        => $result['score'],
                               "scoreType"    => $result['scoreType'],
                               "testDetails"  => $result['testDetails']);

        return $sorted_result;
    }


    /**
     *
     */
    private function printPhonenumber() {
        $phone_numbers = $this->model->getPhoneNumbers();

        $result['name']  = "PHONE_NUMBER";
        $result['hasError'] = FALSE;
        $result['errorMessage'] = NULL;
        $result['testDetails'] = array();
        $result['scoreType'] = $this->scoreType(4);

        if (!empty($phone_numbers)) {
            $phone_numbers_  = array();

            $result['score'] = 40; // TODO: Specify risk

            $result['testDetails'][0]['placeholder'] = "NUMBER_FOUND";

            //$phone_numbers_['comment'] = $this->messages->getMessageByName('PHONE_ONLY');;

            $result['testDetails'][0]['values']['number'] = $phone_numbers;
        } else {
            $result['score'] = 0;

            $result['testDetails'][0] = NULL;
            $result['testDetails'][0] = NULL;

            //$phone_numbers_['comment'] = $this->messages->getMessageByName('NO_PHONE');
            //$phone_numbers_['finding'] = $this->messages->getMessageByName('NO_FINDING');
        }

        $this->global_score += $result['score'];        
        $sorted_result = array("name"         => $result['name'],
                               "hasError"     => $result['hasError'],
                               "errorMessage" => $result['errorMessage'],
                               "score"        => $result['score'],
                               "scoreType"    => $result['scoreType'],
                               "testDetails"  => $result['testDetails']);

        return $sorted_result;
    }

        }
    }
}

?>
