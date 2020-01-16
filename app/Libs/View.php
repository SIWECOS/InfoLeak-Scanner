<?php

namespace App\Libs;

use App\Libs\TranslateableMessage;


/**
 * Returns JSON output of findings.
 */
class View{
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
        5 => "hidden",
        6 => "failed",
    );

    public function scoreType($ordinal) {
        return self::$scoreType_enum[$ordinal];
    }

    public function __construct($version) {
        $this->version = $version;
    }

    public function getScanResult() {
        return $this->scan_result;
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
                }

                if ($isVuln[$j]) {
                    $result['testDetails'][$j] = TranslateableMessage::get(
                        "PLUGIN_VERSION_VULN", ["plugin" => $plugin_name[$j],
                                                "plugin_version" => $version[$j],
                                                "node" => $nodeName[$j],
                                                "node_content" => $f_val[$j]
                        ]
                    );

                    $result['score'] = 0;
                    $this->vuln_count += 1;
                } else {
                    if ($version[$j] === NULL) {
                        $result['testDetails'][$j] = TranslateableMessage::get(
                            "PLUGIN_ONLY", ["plugin" => $plugin_name[$j],
                                            "node" => $nodeName[$j],
                                            "node_content" => $f_val[$j]
                            ]
                        );

                        $result['score'] = 99;
                    } else {
                        $result['testDetails'][$j] = TranslateableMessage::get(
                            "PLUGIN_VERSION", ["plugin" => $plugin_name[$j],
                                               "plugin_version" => $version[$j],
                                               "node" => $nodeName[$j],
                                               "node_content" => $f_val[$j]
                            ]
                        );

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
            $result['scoreType'] = $this->scoreType(6);
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
    private function printJS($nodes, $cms){
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

            foreach($node->attributes as $attribute) {
                if (!empty($lib)) {
                    if (strpos($attribute->value, $lib) !== FALSE) {
                        $finding['node_name'] = $attribute->name;
                        $finding['node_content'] = $attribute->value;

                        break; // attribute found; stop searching
                    }
                }
            }

            $result['testDetails'][0] = TranslateableMessage::get(
                "JS_LIB_ONLY", ["js_lib_name" => $lib,
                                "node" => $finding['node_name'],
                                "node_content" => substr($finding['node_content'], 0, 100)
                ]
            );

            if ((!empty($version)) &&
                ($version !== "N/A")) {
                $result['testDetails'][0] = TranslateableMessage::get(
                    "JS_LIB_VERSION", ["js_lib_name" => $lib,
                                       "js_lib_version" => $version,
                                       "node" => $finding['node_name'],
                                       "node_content" => substr($finding['node_content'], 0, 100)
                    ]
                );

                $result['score'] = 96;
            } else {
                unset($result['version']);
            }

            if ((!empty($isVuln)) &&
                ($isVuln !== "N/A")) {
                $result['testDetails'][0] = TranslateableMessage::get(
                    "JS_LIB_VULN_VERSION", ["js_lib_name" => $lib,
                                            "js_lib_version" => $version,
                                            "node" => $finding['node_name'],
                                            "node_content" => substr($finding['node_content'], 0, 100)
                    ]
                );

                $result['score'] = 0;
                $this->vuln_count += 1;

                /**
                 * Special rule for Wordpress v1.12.4
                 * Score: 90
                 * And it doesn't count as a usual vulnerability
                 * so vuln_count won't get incremented
                 */
                if ($cms["cms"] === "wordpress") {
                    if ($lib === "jquery") {
                        if ($version === "1.12.4") {
                            $result['score'] = 90;
                            $this->vuln_count -= 1;
                        }
                    }
                }
            }

            if ($result['testDetails'][0]['placeholders']['js_lib_name'] === "jquery") {
                if (empty($result['testDetails'][0]['values']['version'])) {
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
            $result['scoreType'] = $this->scoreType(6);
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
                $result['testDetails'][$i] = TranslateableMessage::get(
                    "EMAIL_FOUND", ["email_adress" => $emails[$i]]
                );

                $i++;
            }
        } else {
            $result['score'] = 100;

            $result['testDetails'] = NULL;
        }

        if ($result['hasError']) {
            $result['score'] = 0;
            $result['scoreType'] = $this->scoreType(6);
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
                $result['testDetails'][$i] = TranslateableMessage::get(
                    "NUMBER_FOUND", ["number" => $phone_number]
                );

                $i++;
            }
        } else {
            $result['score'] = 100;
            $result['testDetails'] = NULL;
        }

        if ($result['hasError']) {
            $result['score'] = 0;
            $result['scoreType'] = $this->scoreType(6);
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
     * TODO(ya): This function only gets called when guzzle
     * fails. $errorMessage is retrieved by guzzle and is too verbose
     * in some cases.
     * TODO(ya): Do we want to keep the different ERROR types or would
     * HTTP_ERROR be enough?
     *
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

        // NOTE(ya): remove everything in between brackets
        if (strpos($errorMessage, "(")) {
            $errorMessage = preg_replace('/\([\s\S]+?\)/', '', $errorMessage);
            $errorMessage = rtrim($errorMessage, " ");
        }

        $this->hasError = TRUE;
        $this->errorMessage = TranslateableMessage::get(
            $type, ["description" => substr($errorMessage, 0, 100)]
        );

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
        $tests[] = $this->printPlugin($plugins);
        $tests[] = $this->printJS($jslib, $cms);
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
?>
