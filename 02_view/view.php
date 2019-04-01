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
    private $version = "1.0.5";
    private $model;
    private $controller;
    private $messages;
    private $mode;
    private $scan_count = 5;
    private $global_score = 0;
    /**
     * Max 3
     * Count of vulnerabilities found
     * -> CMS/JS_LIB/PLUGIN are the 3 possibilities
     */
    private $vuln_count = 0;

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
        $cms_node_content = $nodes['node_content'];
        $MAX_FINDING_OUT = 1;
        $result    = array();


        $result['name'] = "CMS";
        $result['hasError'] = $this->controller->getScannerHasError();
        $result['errorMessage'] = $this->controller->getScannerErrorMessage();
        $result['testDetails'] = array();
        $result['scoreType'] = $this->scoreType(4);

        if (!empty($cms)) {
            $result['score'] = 100;

            if (!$version) {
                $result['testDetails'][0]['placeholder'] = "CMS_ONLY";
                $result['testDetails'][0]['values']['cms'] = $cms;
            } else {
                if ($isVuln) {
                    $result['testDetails'][0]['placeholder'] = "CMS_VERSION_VULN";
                    $result['testDetails'][0]['values']['cms'] = $cms;
                    $result['testDetails'][0]['values']['version'] = $version;
                    $result['score'] = 0;
                    $this->vuln_count += 1;
                } else {
                    $result['testDetails'][0]['placeholder'] = "CMS_VERSION";
                    $result['testDetails'][0]['values']['cms'] = $cms;
                    $result['testDetails'][0]['values']['version'] = $version;
                    $result['score'] = 96;
                }
            }
            /*
              if ($cms_node->nodeName === "script") {
              $result['finding'] = preg_replace("/\\n|\\t/", "",
              $cms_node->nextSibling->nodeValue);
              $result['testDetails'][0]['values']['node'] = $cms_node->nodeName;

              if (strlen($result['finding']) > 100) {
              $result['finding']  = substr($result['finding'], 0, 100);
              $result['finding'] .= " [...]";
              }
              $result['testDetails'][0]['values']['node_content'] = $result['finding'];
              } else {
              $i = 0;

              foreach($cms_node->attributes as $attr) {
              $finding = $attr->name . " : " . $attr->value;

              if ($i < $MAX_FINDING_OUT)
              $i++;
              else
              break;
              }

            */
            if (strlen($cms_node_content) > 100) {
                $cms_node_content  = substr($cms_node_content, 0, 100);
                $cms_node_content .= " [...]";
            }

            if (is_string($cms_node)) {
                $result['testDetails'][0]['values']['node'] = $cms_node;
            } else {
                $result['testDetails'][0]['values']['node'] = $cms_node->nodeName;
            }

            $result['testDetails'][0]['values']['node_content'] = $cms_node_content;
        } else {
            $result['score']      = 100;
            $result['testDetails'] = NULL;
        }

        if ($result['hasError']) {
            $result['score'] = 0;
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
        $result['hasError'] = $this->controller->getScannerHasError();
        $result['errorMessage'] = $this->controller->getScannerErrorMessage();
        $result['testDetails'] = array();
        $result['scoreType'] = $this->scoreType(1);

        if (count($nodes) > 1) {
            $isVuln   = $nodes['result'];
            $f_val    = $nodes['pVal'];
            $nodeName = $nodes['attrName'];
            $version  = $nodes['version'];
            $plugin_name = $nodes['plugin_name'];
            $result['score'] = 0;

            $limit = 1;
            if (count($isVuln) < $limit)
                $limit = count($isVuln);


            for ($j=0; $j < $limit; $j++) {
                if ($isVuln[$j] === NULL)
                    break;

                if (strlen($f_val[$j]) > 100) {
                    $f_val[$j]  = substr($f_val[$j], 0, 100);
                    $f_val[$j] .= " [...]";
                }

                if ($isVuln[$j]) {
                    $result['testDetails'][$j]['placeholder'] = "PLUGIN_VERSION_VULN";
                    $result['testDetails'][$j]['values']['plugin'] = $plugin_name[$j];
                    $result['testDetails'][$j]['values']['plugin_version'] = $version[$j];
                    $result['testDetails'][$j]['values']['node'] = $nodeName[$j];
                    $result['testDetails'][$j]['values']['node_content'] = $f_val[$j];
                    $result['score'] = 0;
                    $this->vuln_count += 1;
                } else {
                    if ($version[$j] === NULL) {
                        $result['testDetails'][$j]['placeholder'] = "PLUGIN_ONLY";
                        $result['testDetails'][$j]['values']['plugin'] = $plugin_name[$j];
                        $result['testDetails'][$j]['values']['node'] = $nodeName[$j];
                        $result['testDetails'][$j]['values']['node_content'] = $f_val[$j];
                        $result['score'] = 99;
                    } else {
                        $result['testDetails'][$j]['placeholder'] = "PLUGIN_VERSION";
                        $result['testDetails'][$j]['values']['plugin'] = $plugin_name[$j];
                        $result['testDetails'][$j]['values']['plugin_version'] = $version[$j];
                        $result['testDetails'][$j]['values']['node'] = $nodeName[$j];
                        $result['testDetails'][$j]['values']['node_content'] = $f_val[$j];
                        $result['score'] = 96;
                    }
                }
            }
        } else {
            $result['score'] = 100;

            $result['testDetails'] = NULL;
        }

        if ($result['hasError']) {
            $result['score'] = 0;
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
        $node    = $nodes['node'];
        $result  = $finding = array();

        $result['name']  = "JS_LIB";
        $result['hasError'] = $this->controller->getScannerHasError();
        $result['errorMessage'] = $this->controller->getScannerErrorMessage();
        $result['testDetails'] = array();
        $result['testDetails'][0] = array();
        $result['scoreType'] = $this->scoreType(1);

        if (!empty($node)) {
            $result['score'] = 99;

            $result['testDetails'][0]['placeholder'] = "JS_LIB_ONLY";
            $result['testDetails'][0]['values']['js_lib_name'] = $lib;


            foreach($node->attributes as $attribute) {
                if (!empty($lib)) {
                    if (strpos($attribute->value, $lib) !== FALSE) {
                        $finding['node_name'] = $attribute->name;
                        $finding['node_content'] = $attribute->value;

                        break; // attribute found; stop searching
                    }
                }
            }

            if ((!empty($version)) &&
                ($version !== "N/A")) {
                $result['testDetails'][0]['placeholder'] = "JS_LIB_VERSION";
                $result['testDetails'][0]['values']['js_lib_name'] = $lib;
                $result['testDetails'][0]['values']['js_lib_version'] = $version;
                $result['score'] = 96;
            } else {
                unset($result['version']);
            }

            if ((!empty($isVuln)) &&
                ($isVuln !== "N/A")) {
                $result['testDetails'][0]['placeholder'] = "JS_LIB_VULN_VERSION";
                $result['testDetails'][0]['values']['js_lib_name'] = $lib;
                $result['testDetails'][0]['values']['js_lib_version'] = $version;
                $result['score'] = 0;
                $this->vuln_count += 1;

                /**
                 * Special rule for Wordpress v1.12.4
                 * Score: 90
                 * And it doesn't count as a usual vulnerability
                 * so vuln_count won't get incremented
                 */
                if ($this->model->getCMS()['cms'] === "wordpress") {
                    if ($lib === "jquery") {
                        if ($version === "1.12.4") {
                            $result['score'] = 90;
                            $this->vuln_count -= 1;
                        }
                    }
                }
            }

            if (!empty($finding['node_content'])) {
                if (strlen($finding['node_content']) >= 100) {
                    $finding['node_content'] = substr($finding['node_content'], 0, 100);
                    $finding['node_content'] .= " [...]";
                }
            }

            $result['testDetails'][0]['values']['node'] = $finding['node_name'];
            $result['testDetails'][0]['values']['node_content'] = $finding['node_content'];

            if ($result['testDetails'][0]['values']['js_lib_name'] === "jquery") {
                if (empty($result['testDetails'][0]['values']['js_lib_version'])) {
                    $result['score'] = 100;
                    $result['testDetails'] = NULL;
                }
            }
        } else {
            $result['score'] = 100;
            $result['testDetails'] = NULL;
        }

        if ($result['hasError']) {
            $result['score'] = 0;
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
        $result['hasError'] = $this->controller->getScannerHasError();
        $result['errorMessage'] = $this->controller->getScannerErrorMessage();
        $result['testDetails'] = array();
        $result['scoreType'] = $this->scoreType(4);

        if (!empty($emails)) {
            $result['score']   = 96;

            $i = 0;
            foreach ($emails as $email) {
                $result['testDetails'][$i]['placeholder'] = "EMAIL_FOUND";

                $result['testDetails'][$i]['values']['email_adress'] = $emails[$i];
                $i++;
            }
        } else {
            $result['score'] = 100;

            $result['testDetails'] = NULL;
        }

        if ($result['hasError']) {
            $result['score'] = 0;
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
        $result['hasError'] = $this->controller->getScannerHasError();
        $result['errorMessage'] = $this->controller->getScannerErrorMessage();
        $result['testDetails'] = array();
        $result['scoreType'] = $this->scoreType(4);

        if (!empty($phone_numbers)) {
            $phone_numbers_  = array();

            $result['score'] = 98;
            $result['testDetails'][0]['placeholder'] = "NUMBER_FOUND";

            $result['testDetails'][0]['values']['number'] = $phone_numbers;
        } else {
            $result['score'] = 100;
            $result['testDetails'] = NULL;
        }

        if ($result['hasError']) {
            $result['score'] = 0;
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
    public function printJSON($mode) {
        $result = array();
        $tests  = array();

        /* Scan results */
        $tests[] = $this->printCMS();
        $tests[] = $this->printPlugin();
        $tests[] = $this->printJS();
        $tests[] = $this->printEmail();
        $tests[] = $this->printPhonenumber();

        /* Scanner details - overall */
        $result["name"] = "INFOLEAK";
        $result["version"] = $this->version;
        $result["hasError"] = $this->controller->getScannerHasError();
        $result["errorMessage"] = $this->controller->getScannerErrorMessage();

        if ($this->vuln_count > 0) {
            $result["score"] = (20 - (($this->vuln_count-1) * 10));
        } else if ($result['hasError']) {
            $result['score'] = 0;
        } else {
            $result["score"] = round($this->global_score/$this->scan_count);
        }

        $result["tests"] = $tests;

        $this->scan_result = $result;

        if ($mode === "GET") {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($this->scan_result,
                             JSON_PRETTY_PRINT |
                             JSON_UNESCAPED_UNICODE |
                             JSON_UNESCAPED_SLASHES);

            return $result;
        } else if ($mode === "POST") {
            $this->controller->send_to_callbackurls($this->getScanResult());
        }
    }
}

?>
