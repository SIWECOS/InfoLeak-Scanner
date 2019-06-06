<?php

namespace App\Libs;

use App\Libs\Messages;
use App\Libs\TranslateableMessage;


/**
 * Returns JSON output of findings.
 */
class View{
    private $messages;
    private $scan_count = 4; // NOTE(ya): decreased by 1 - CMS SCAN got obsolete (but still built-in)
    private $global_score = 0;
    private $version;
    private $vuln_count = 0;

    private $scan_result;
    private $hasError = false;
    private $errorMessage = NULL;

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

    public function __construct($version) {
        $this->messages   = new Messages();
        $this->version = $version;
    }

    public function getScanResult() {
        return $this->scan_result;
    }

    private function printCMS($nodes) {
        $result['name'] = "CMS";
        $result['hasError'] = $this->hasError;
        $result['errorMessage'] = $this->errorMessage;
        $result['scoreType'] = $this->scoreType(4);
        $result['testDetails'] = array();

        if ($nodes === NULL)
            return $result;

        $isVuln   = $nodes['isVuln'];
        $version  = $nodes['version'];
        $cms      = $nodes['cms'];
        $cms_node = $nodes['node'];
        $cms_node_content = $nodes['node_content'];
        $MAX_FINDING_OUT = 1;
        $result    = array();

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
    private function printPlugin($nodes) {
        $result  = array();

        $result['name']  = "CMS_PLUGINS";
        $result['hasError'] = $this->hasError;
        $result['errorMessage'] = $this->errorMessage;
        $result['scoreType'] = $this->scoreType(1);
        $result['testDetails'] = array();

        if ($nodes["result"] !== NULL) {
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
    private function printJS($nodes){
        $result  = $finding = array();
        $result['name']  = "JS_LIB";
        $result['hasError'] = $this->hasError;
        $result['errorMessage'] = $this->errorMessage;
        $result['scoreType'] = $this->scoreType(1);
        $result['testDetails'] = array();

        $isVuln  = $nodes['isVuln'];
        $version = $nodes['version'];
        $lib     = $nodes['lib'];
        $node    = $nodes['node'];

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
                if ($cms === "wordpress") {
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
    private function printEmail($emails) {
        $j = 0;

        $result['name']  = "EMAIL_ADDRESS";
        $result['hasError'] = $this->hasError;
        $result['errorMessage'] = $this->errorMessage;
        $result['scoreType'] = $this->scoreType(4);
        $result['testDetails'] = array();

        // TODO(ya): 
        // if ($emails === NULL) {
        //     return $result;
        // }

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
    private function printPhonenumber($phone_numbers) {
        $result['name']  = "PHONE_NUMBER";
        $result['hasError'] = $this->hasError;
        $result['errorMessage'] = $this->errorMessage;
        $result['scoreType'] = $this->scoreType(4);
        $result['testDetails'] = array();

        // TODO(ya): 
        // if ($phone_numbers === NULL)
        //     return $result;

        if (!empty($phone_numbers)) {
            $phone_numbers_  = array();

            $result['score'] = 98;

            $i = 0;
            foreach ($phone_numbers as $phone_number) {
                $result['testDetails'][$i]['placeholder'] = "NUMBER_FOUND";
                $result['testDetails'][$i]['values']['number'] = $phone_number;
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
     * Something went wrong. Print error message according specifications.
     *
     * Possible types:
     * REQUEST_ERROR, TRANSFER_ERROR, CONNECT_ERROR, CLIENT_ERROR,
     * SERVER_ERROR, TOOMANYREDIRECTS_ERROR, BADRESPONSE_ERROR
     *
     * @return array
     */
    public function printError($errorMessage, $type) {
        $type = strtoupper(str_replace("Exception", "", explode("\\", $type)[2])) . "_ERROR";

        $this->hasError = TRUE;
        $this->errorMessage["placeholder"] = $type;
        $this->errorMessage["values"]["description"] = $errorMessage;

        $result = array();
        $tests  = array();

        /* Scanner details - overall */
        $result["name"] = "INFOLEAK";
        $result["version"] = $this->version;
        $result["hasError"] = $this->hasError;
        $result["errorMessage"] = $this->errorMessage;

        if ($this->vuln_count > 0) {
            $result["score"] = (20 - (($this->vuln_count-1) * 10));
        } else if ($result['hasError']) {
            $result['score'] = 0;
        } else {
            $result["score"] = round($this->global_score/$this->scan_count);
        }

        $result["tests"] = [];

        $this->scan_result = $result;

        return $result;
    }

    /**
     * Runs individual print functions to extract scanner results.
     * @return array
     */
    public function printJSON($cms, $email, $plugins, $jslib, $phonenumber) {
        $result = array();
        $tests  = array();

        /* Scan results */
        //$tests[] = $this->printCMS($cms);
        $tests[] = $this->printPlugin($plugins);
        $tests[] = $this->printJS($jslib);
        $tests[] = $this->printEmail($email);
        $tests[] = $this->printPhonenumber($phonenumber);

        /* Scanner details - overall */
        $result["name"] = "INFOLEAK";
        $result["version"] = $this->version;
        $result["hasError"] = $this->hasError;
        $result["errorMessage"] = $this->errorMessage;

        if ($this->vuln_count > 0) {
            $result["score"] = (20 - (($this->vuln_count-1) * 10));
        } else if ($result['hasError']) {
            $result['score'] = 0;
        } else {
            $result["score"] = round($this->global_score/$this->scan_count);
        }

        $result["tests"] = $tests;

        $this->scan_result = $result;

        return $result;
    }
}

/**
 * All possible scoreTypes.
 */
abstract class scoreType {
    const critical = 0;
    const warning = 1;
    const success = 2;
    const bonus = 3;
    const info = 4;
    const hidden = 5;
}

class ScanTemplate {
    public $name = "Unknown";
    public $hasError = false;
    public $errorMessage = NULL;
    public $score = 0;
    public $scoreType = scoreType::info;
    public $testDetails = [];
}
?>
