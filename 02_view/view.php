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

    public function __construct($model, $controller) {
        $this->model      = $model;
        $this->controller = $controller;

        $this->messages   = new Messages();
        //echo $messages->getMessageById(0);
        //echo $messages->getMessageByName('test');

        
        // Print verbose:
        $this->printJSON(TRUE);
        
        // Don't print verbose:
        //$this->printJSON();
    }

    /**
     * The JSON output is specified as follows:
     *
     * {
     * "checks": {
     *   "cms": {
     *       "result": true,
     *       "risk": 6,
     *       "comment": "Die verwendete CMS konnte ermittelt werden (wordpress).",
     *       "finding": "[meta]: content : WordPress"
     *   },
     *   "plugin": {
     *       [...]
     *   },
     *   "javascript": {
     *       [...]
     *   },
     *   "email": {
     *       [...]
     *   },
     *   "phone": {
     *       [...]
     *   }
     *  }
     * }
     */
    public function printJSON($detailed=FALSE) {
        $result          = array();
        $MAX_FINDING_OUT = 2;


        /****************************************/
        $nodes    = $this->model->getCMS();

        $isVuln   = $nodes['isVuln'];
        $version  = $nodes['version'];
        $cms      = $nodes['cms'];
        $cms_node = $nodes['node'];
        $node_    = array();

        if (!empty($cms)) {
            $node_['risk'] = 6; // TODO: higher/lower risk if version was detected etc

            if (!$version) {
                $node_['comment'] = $this->messages->getMessageByName('CMS_ONLY',
                                                                      $cms);
            } else {
                if ($isVuln) {
                    //$node_['risk'] = 10;
                    $node_['comment'] = $this->messages->getMessageByName('CMS_VERSION_VULN',
                                                                          $cms . " " . $version);
                } else {
                    //$node_['risk'] = 8;
                    $node_['comment'] = $this->messages->getMessageByName('CMS_VERSION',
                                                                          $cms . " " . $version);
                }
            }

            if ($cms_node->nodeName === "script") {
                $node_['finding'] = preg_replace("/\\n|\\t/", "",
                                                 $cms_node->nextSibling->nodeValue);

                if (strlen($node_['finding']) > 100) {
                    $node_['finding']  = substr($node_['finding'], 0, 100);
                    $node_['finding'] .= " [...]";
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

                $node_['finding'] = preg_replace("/\\n|\\t/", "",
                                                 "[" . $cms_node->nodeName . "]"
                                                 . ": " . $finding);
            }

            //$node_['result'] = $isVuln;
            $node_['result'] = TRUE;

            if ($detailed === TRUE) {
                $sorted_node_ = array("result"  => $node_['result'],
                                      "risk"    => $node_['risk'],
                                      "comment" => $node_['comment'],
                                      "finding" => $node_['finding']);
            } else {
                $sorted_node_ = array("result"  => $node_['result'],
                                      "risk"    => $node_['risk']);
            }

            $result["checks"]["cms"] = $sorted_node_;
        } else {
            $node_['result'] = FALSE;
            $node_['risk']   = 0;

            if ($detailed === TRUE) {
                $node_['comment'] = $this->messages->getMessageByName('NO_CMS');
                $node_['finding'] = $this->messages->getMessageByName('NO_FINDING');
            }

            $result["checks"]["cms"] = $node_;
        }

        /****************************************/
        $nodes = $this->model->getPlugin();

        if (count($nodes) > 1) {
            $isVuln  = $nodes['result'];
            $f_val   = $nodes['pVal'];
            $version = $nodes['version'];
            $plugin_name = $nodes['plugin_name'];
            //$comment = $nodes['comment'];
            $nodes_  = array();

            $nodes_['result'] = TRUE;
            $nodes_['risk']   = 7; // TODO: higher/lower risk if version was detected etc

            $limit = $MAX_FINDING_OUT+1;
            if (count($isVuln) < $limit)
                $limit = count($isVuln);

            for ($j=0; $j < $limit; $j++) {
                if ($isVuln[$j] === NULL)
                    break;

                if (strlen($f_val[$j]) > 100) {
                    $f_val[$j]  = substr($f_val[$j], 0, 100);
                    $f_val[$j] .= " [...]";
                }

                //$nodes_['result'][] = $isVuln[$j];
                if ($detailed === TRUE) {
                    if ($isVuln[$j]) {
                        //$nodes_['comment'][] = $comment[$j];
                        $nodes_['comment'][] = $this->messages->getMessageByName('PLUGIN_VERSION_VULN', $plugin_name[$j] . " " . $version[$j]);
                        $nodes_['finding'][] = $f_val[$j];
                    } else {
                        if ($version[$j] === NULL) {
                            $nodes_['comment'][] = $this->messages->getMessageByName('PLUGIN_ONLY', $plugin_name[$j]);
                            $nodes_['finding'][] = $f_val[$j];
                        } else {
                            $nodes_['comment'][] = $this->messages->getMessageByName('PLUGIN_ONLY', $plugin_name[$j] . " " . $version[$j]);
                            $nodes_['finding'][] = $f_val[$j];
                        }
                    }
                }
            }

            if ($limit === 1) {
                if ($detailed === TRUE) {
                    $nodes_['comment'] = implode("", $nodes_['comment']);
                    $nodes_['finding'] = implode("", $nodes_['finding']);
                }
            }
        } else {
            $nodes_['result'] = FALSE;
            $nodes_['risk']   = 0;

            if ($detailed === TRUE) {
                $nodes_['comment'] = $this->messages->getMessageByName('NO_PLUGINS');
                $nodes_['finding'] = $this->messages->getMessageByName('NO_FINDING');
            }
        }
        $result["checks"]["plugin"] = $nodes_;

        /****************************************/
        $nodes   = $this->model->getJSLib();
        $isVuln  = $nodes['isVuln'];
        $version = $nodes['version'];
        $lib     = $nodes['lib'];
        $nodes   = $nodes['nodes'];

        if (!empty($nodes)) {
            $node_  = $finding = array();
            $i = $j = 0;
            $node_['result']   = TRUE;
            $node_['risk']     = 5;
            $node_['comment']  = $this->messages->getMessageByName('JS_ONLY',
                                                                   $lib[$i]);

            foreach($nodes as $node) {
                /* Print only 2 finding nodes. */
                if ($j < $MAX_FINDING_OUT)
                    $j++;
                else
                    break;

                foreach($node->attributes as $attribute) {
                    $finding['attr'] = $attribute->value;

                    if (strlen($finding['attr']) > 100) {
                        $finding['attr']  = substr($finding['attr'], 0, 100);
                        $finding['attr'] .= " [...]";
                    }
                }

                if ((!empty($version[$i])) &&
                   ($version[$i] !== "N/A")) {
                    //$node_['risk'] = 6;
                    $finding['version'] = $version[$i];

                    $node_['comment']   = $this->messages->getMessageByName('JS_VERSION',
                                                                            $lib[$i] . " " . $version[$i]);
                } else {
                    unset($node_['version']);
                }

                if ((!empty($isVuln[$i])) &&
                   ($isVuln[$i] !== "N/A")) {
                    //$node_['risk'] = 8;
                    //$node_['result'] = $isVuln[$i];

                    $node_['comment']   = $this->messages->getMessageByName('JS_VULN_VERSION',
                                                                           $lib[$i] . " " . $version[$i]);
                }
                // else {
                //     $node_['result'] = FALSE;
                // }

                $i++;
                $node_['finding'] = $finding;
            }
        } else {
            $node_['result']  = FALSE;
            $node_['risk']    = 0;
            $node_['comment'] = $this->messages->getMessageByName('NO_JS');
            $node_['finding'] = $this->messages->getMessageByName('NO_FINDING');
        }

        if ($detailed === TRUE) {
            $sorted_node_ = array("result"  => $node_['result'],
                                  "risk"    => $node_['risk'],
                                  "comment" => $node_['comment'],
                                  "finding" => $node_['finding']);
        } else {
            $sorted_node_ = array("result"  => $node_['result'],
                                  "risk"    => $node_['risk']);
        }

        $result["checks"]["javascript"] = $sorted_node_;

        /****************************************/
        $emails = $this->model->getEmail();
        $j = 0;

        if (!empty($emails)) {
            $emails_ = array();

            $emails_['result'] = TRUE;
            $emails_['risk']   = 7;

            if ($detailed === TRUE) {
                $emails_['comment'] = $this->messages->getMessageByName('EMAIL_ONLY');

                $emails_['finding'] = NULL;
                foreach($emails as $email) {
                    $emails_['finding'] .= $email . ", ";
                }
                $emails_['finding'] = substr($emails_['finding'], 0,
                                             strlen($emails_['finding'])-2);
            }
        } else {
            $emails_['result'] = FALSE;
            $emails_['risk']   = 0;

            if ($detailed === TRUE) {
                $emails_['comment'] = $this->messages->getMessageByName('NO_EMAIL');
                $emails_['finding'] = $this->messages->getMessageByName('NO_FINDING');
            }
        }
        $result["checks"]["email"] = $emails_;

        /****************************************/
        $phone_numbers = $this->model->getPhoneNumbers();
        if (!empty($phone_numbers)) {
            $phone_numbers_ = array();

            $phone_numbers_['result'] = TRUE;
            $phone_numbers_['risk']   = 4; // TODO: Specify risk

            if ($detailed === TRUE) {
                $phone_numbers_['comment'] = $this->messages->getMessageByName('PHONE_ONLY');;

                $phone_numbers_['finding'] = NULL;
                foreach($phone_numbers as $phone_number) {
                    $phone_numbers_['finding'] .= $phone_number . ", ";
                }
                $phone_numbers_['finding'] = substr($phone_numbers_['finding'], 0,
                                                    strlen($phone_numbers_['finding'])-2);
            }
        } else {
            $phone_numbers_['result'] = FALSE;
            $phone_numbers_['risk']   = 0;

            if ($detailed === TRUE) {
                $phone_numbers_['comment'] = $this->messages->getMessageByName('NO_PHONE');
                $phone_numbers_['finding'] = $this->messages->getMessageByName('NO_FINDING');
            }
        }
        $result["checks"]["phone"] = $phone_numbers_;

        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($result,
                         JSON_PRETTY_PRINT |
                         JSON_UNESCAPED_UNICODE |
                         JSON_UNESCAPED_SLASHES);
        return $result;
    }
}

?>
