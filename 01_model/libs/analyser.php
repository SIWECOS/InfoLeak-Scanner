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

include 'searcher.php';
include 'remover.php';
// https://github.com/giggsey/libphonenumber-for-php
require __DIR__ . '/../../vendor/autoload.php';

// Set maximum execution time to 5 minutes
ini_set('max_execution_time', 300);

class Analyser {
    private $url;
    private $source;
    private $searcher;

    public function __construct($url, $source) {
        $this->url = $url;
        
        /**
         * Detect chinese characters and decode
         */
        if (preg_match("/\p{Han}+/u", $source)) {
            $this->source = html_entity_decode($source);
        } else {
            $this->source = $source;
        }

        $this->searcher = new Searcher($this->source);
    }


    /**
     * @short: Searches E-Mail addresses
     * @Note: Regex used:
     * (?:[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:(\.|\s*\[dot\]\s*)[a-z0-9!#$%&'*+\/=?^
     * _`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x0
     * 1-\x09\x0b\x0c\x0e-\x7f])*")
     * (@|\s*\[at\]\s*)
     * (?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|(\s*\[dot\]\s*)))+)([a-z]{2,})\b
     * @return array
     * TODO: What is better? TLD within regex or filtering afterwards?
     */
    public function find_email($source) {
        $remover = new Remover($this->source);
        /**
         * Minimize DOM for performance
         */
        $toRemove = array("script", "path", "polygon", "polyline", "svg",
                          "symbol", "source", "style", "audio", "applet",
                          "basefont", "button", "canvas", "map", "menu", "nav",
                          "progress", "time");
        foreach ($toRemove as $node) {
            $source = $remover->removeNode($source, $node);
        }

        $toRemove = array("data-module-id", "data-tl-id", "data-bem", "src",
                          "bgcolor", "border", "buffered", "cite", "class",
                          "color", "datetime", "height", "href", "icon",
                          "id", "maxlength", "media", "rel", "size", "sizes",
                          "style", "value", "width", "alt");
        foreach ($toRemove as $node) {
            $source = $remover->removeAttribute($source, $node);
        }

        /* Generic */
        $top_level_domains  = "com|org|net|int|edu|gov|mil|";
        /* Country */
        $top_level_domains .= "arpa|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|";
        $top_level_domains .= "au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|";
        $top_level_domains .= "bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|";
        $top_level_domains .= "cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|";
        $top_level_domains .= "dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|";
        $top_level_domains .= "gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|";
        $top_level_domains .= "gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|";
        $top_level_domains .= "is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|";
        $top_level_domains .= "kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|";
        $top_level_domains .= "mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|";
        $top_level_domains .= "my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|";
        $top_level_domains .= "pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|";
        $top_level_domains .= "rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|";
        $top_level_domains .= "so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|";
        $top_level_domains .= "tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|us|uy|uz|va|";
        $top_level_domains .= "vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw";


        $local_part  = "/(?:[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:(\.|\s*(\[|\()(do|punk)t(\]|\))\s*)";
        $local_part .= "[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x";
        $local_part .= "0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x";
        $local_part .= "0c\x0e-\x7f])*\")";

        $seperator = "(@|\s*(\[|\()at(\]|\))\s*)";

        $domain_part = "(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|(\s*(\[|\()(";
        //$domain_part .= "do|punk)t(\]|\))\s*)))+)([a-z]{2,})\b/i";
        $domain_part .= "do|punk)t(\]|\))\s*)))+)" . "(" . $top_level_domains
                     .  ")" . "\b/i";


        $regex = $local_part . $seperator . $domain_part;

        preg_match_all($regex, $source, $result);

        $result = array_values(array_unique($result[0], SORT_REGULAR));

        return $result;
    }


    /**
     * @short: Detect version number in given string
     * @algorithm: Uses a regex to find version numbers like 1.0.4
     * @var: all return the whole finding (TRUE) or just version number (FALSE)
     * @return array
     */
    public function getVersionNumber($string, $all=FALSE) {
        $regex = "/(?:(\d+)\.)(?:(\d+)\.)(\*|\d+)*/";

        preg_match($regex, $string, $result);

        if ($all === FALSE) {
            if (!empty($result[0]))
                return $result[0];
            else
                return NULL;
        } else {
            if (!empty($result[0]))
                return $result;
            else
                return NULL;
        }
    }


    /**
     * @short: Searches phone and fax numbers.
     *
     * Note: https://de.wikipedia.org/wiki/Rufnummer#Schreibweisen
     * @return array
     */
    public function find_phoneNumber($source, $nation="DE") {
        //$source = preg_replace("/&#?[a-z0-9]{2,8};/", "", $source);
        //$source = preg_replace("/\p{Han}+/", '', $source);

        $remover = new Remover($this->source);

        // remove anchor tags if a phone number is not linked via "tel:"
        $number_in_url = $this->searcher->in_a("tel");
        if (empty($number_in_url)) {
            $source = $remover->removeNode($source, "a");
        }

        /**
         * Delete potential false-positive tags/attributes
         */
        $toRemove = array("script", "path", "polygon", "polyline", "svg",
                          "symbol", "source", "style", "audio", "applet",
                          "basefont", "button", "canvas", "map", "menu", "nav",
                          "progress", "time", "area", "img");
        foreach ($toRemove as $node) {
            $source = $remover->removeNode($source, $node);
        }

        $toRemove = array("data-module-id", "data-tl-id", "data-bem", "src",
                          "data-city-x-coord", "data-city-y-coord", "_lazy",
                          "bgcolor", "border", "buffered", "cite", "class",
                          "color", "datetime", "height", "href", "icon",
                          "id", "maxlength", "media", "rel", "size", "sizes",
                          "style", "value", "width", "alt", "data-reactid",
                          "_videoid");
        foreach ($toRemove as $node) {
            $source = $remover->removeAttribute($source, $node);
        }

        $source = $remover->removeEvents($source);
        $source = $remover->removeComments($source);
        $source = $remover->removeData($source);
        //$source = $remover->removeKISSY($source);

        $source = $remover->removeAllAttribute($source, "div");

        //$source = preg_replace("/&#?[a-z0-9]{2,8};/i", "", $source);
        //$source = preg_replace("/\p{Han}+/u", '', $source);
        //echo htmlspecialchars($source);
        //return;

        $result = array();
        $phoneNumberUtil    = \libphonenumber\PhoneNumberUtil::getInstance();

        $phoneNumberMatcher = $phoneNumberUtil->findNumbers($source, $nation);

        foreach ($phoneNumberMatcher as $phoneNumberMatch) {
            $phoneNumber = $phoneNumberMatch->rawString();

            /**
             * Given phonenumber will probably not contain a '.' _and_ '-' so
             * filter that.
             */
            if ((strpos($phoneNumber, '.') !== false)
                && (strpos($phoneNumber, '-') !== false)) {
                continue;
            }

            /**
             * Potential phone numbers with too many '/' are probably no phone
             * numbers.
             */
            if (substr_count($phoneNumber, '/') > 2) {
                continue;
            }

            if (strpos($phoneNumber, '&#') !== false) {
                continue;
            }

            /**
             * Phone numbers in general start with 0, ( or a +. Filter anything
             * else.
             */
            if (($phoneNumber[0] != "0")
                && ($phoneNumber[0] != "+")
                && ($phoneNumber[0] != "(")) {
                continue;
            }

            /**
             * Filter is_numeric() types which are not relevant here
             */
            if ((strpos($phoneNumber, 'b') !== false)
                || (strpos($phoneNumber, 'e') !== false)) {
                continue;
            }

            /* Check if phoneNumber is a date (false-positive) */
            if (strpos($phoneNumber, '.')) {
                $date = explode('.', $phoneNumber);
            } else if (strpos($phoneNumber, '-')) {
                $date = explode('-', $phoneNumber);
            } else {
                $date = ' ';
            }

            $date = str_replace(' ', '', $date);
            if (!empty($date)) {
                if (count($date) === 3) {  // it contains 2 dots
                    // expect years to be at maximum 10 years from now
                    if ($date[2] > (date("Y")+10)) {
                        continue;
                    }
                    if (($date[0] <= 12) && ($date[1] <= 31)) {
                        if (checkdate($date[0], $date[1], $date[2])) {
                            continue;
                        }
                    } else if (($date[1] <= 12) && ($date[0] <= 31)) {
                        if (checkdate($date[1], $date[0], $date[2])) {
                            continue;
                        }
                    }
                }
            }
            $result[] = $phoneNumberMatch->rawString();
        }
        $result = array_unique($result);

        return $result;
    }


    /**
     * @short: Searches the source for plugins of the given CMS.
     * @var CMS: Select CMS for the specific plugins.
     * @var file: Specifies the wordfile.
     * @var plugins: Contains the plugins found in source.
     * TODO: Search via XPath - not filtered yet :(.
     * @return array
     */
    public function analyse_plugins($CMS) {
        $remover = new Remover($this->source);
        /**
         * Delete potential false-positive tags/attributes
         */
        $toRemove = array("script");
        foreach ($toRemove as $node) {
            $source = $remover->removeNode($this->source, $node);
        }

        $file          = NULL;
        $vulnCheckSite = NULL;

        /* We can only look for plugins if we know the CMS*/
        if (!empty($CMS)) {
            switch ($CMS) {
            case "wordpress":
            case "wp-content":
                $file = "./wordfiles/Plugins/WPPlugins.conf";
                //$vulnCheckSite = "https://wpvulndb.com/search?utf8=TRUE&text=";
                break;
            case "drupal":
                $file = "./wordfiles/Plugins/DrupPlugins.conf";
                break;
            }

            if ($file !== NULL) {
                $plugins        = array();
                $vulnCheck_list = array();
                $result         = array();
                $isVuln         = array();
                $pVal           = array();
                $cnt            = 0;

                $target_attributes = array(
                    "href",
                    "src",
                    "data",
                    "poster",
                    "codebase"
                );

                $lines = file($file, FILE_IGNORE_NEW_LINES);
                $first = $second = $third = 0;
                foreach ($lines as $line) {
                    $nodes = $this->searcher->in_all_caseInsensitive($line);

                    if (!empty($nodes->length)) {
                        foreach ($nodes as $node) {
                            /* Filter attributes */
                            foreach ($node->attributes as $attr) {
                                if (in_array($attr->name, $target_attributes)) {
                                    $line_pos = strpos($attr->value, $line);
                                    $next_char = substr($attr->value, $line_pos+strlen($line), 1) . "\r\n";

                                    preg_match('/[a-zA-Z0-9]/', $next_char, $check_char);
                                    if (!empty($check_char)) {
                                        break 2;
                                    }

                                    $prev_char = substr($attr->value, $line_pos-1, 1) . "\r\n";
                                    preg_match('/[a-zA-Z0-9#-]/', $prev_char, $check_char1);
                                    if (!empty($check_char1)) {
                                        break 2;
                                    }

                                    if (strpos($attr->value, ".js")) {
                                        break 2;
                                    }


                                    if ($line_pos !== FALSE) {
                                        /* Found plugin */
                                        //$plugins[] = $node;
                                        $pVal[]    = $attr->value;
                                        $vuln_file = "./wordfiles/Plugins/WPvulnDB/" . $line . ".conf";

                                        if (file_exists($vuln_file)) {
                                            $known_vulnCount = count(file($vuln_file));
                                            $found_plugin_v  = $this->getVersionNumber($attr->value);

                                            $vuln_plugins = file($file, FILE_IGNORE_NEW_LINES);
                                            foreach ($vuln_plugins as $vuln_line) {
                                                $vuln_version = $this->getVersionNumber($vuln_line);

                                                if ($vuln_version === $found_plugin_v) {
                                                    if ($vuln_version !== NULL) {
                                                        $result['result'][] = TRUE;
                                                        $result['plugin_name'][] = $line;
                                                        $result['version'][] = $vuln_version;
                                                        break 4;
                                                    }
                                                }
                                            }
                                        }
                                        $result['result'][]      = FALSE;
                                        $result['version'][]     = NULL;
                                        $result['plugin_name'][] = $line;
                                        $result['attrName'][]    = $attr->name;

                                        $cnt++;
                                        if ($cnt === 3)
                                            break 3;
                                        else
                                            break 2;
                                    }
                                }
                            }
                        }
                    }
                }
                //$result['node'] = $plugins;
                $result['pVal'] = $pVal;

                return $result;
            } else {
                return NULL;
            }
        } else {
            return NULL;
        }
    }

    /**
     *
     */
    public function analyse_cms_version($regex, $attribute_value,
                                        $vuln_if_smaller, $vuln_array) {
        // check if it contains version
        $version_regex = $regex;
        if (preg_match($version_regex, $attribute_value, $match) === 1) {
            $version = $match[1];

            // version detected and set
            $result['version'] = $version;
        } else {
            // no version number
            $result['version'] = NULL;
        }

        if ($result['version'] !== NULL) {
            $vuln_versions = $vuln_array;
            $isVuln = FALSE;

            // check specific version defined in array
            foreach ($vuln_versions as $vuln) {
                if ($vuln === $result['version']) {
                    $isVuln = TRUE;
                }
            }

            $split_version = explode(".", $result['version']);
            if ((int)$split_version[0] !== NULL) {
                if ((int)$split_version[0] < $vuln_if_smaller[0]) {
                    $isVuln = TRUE;
                } else if ((int)$split_version[0] === 4) {
                    if ((int)$split_version[1] !== NULL) {
                        if ((int)$split_version[1] <= $vuln_if_smaller[1]) {
                            if ((int)$split_version[2] !== NULL) {
                                if ((int)$split_version[2] <= $vuln_if_smaller[2]) {
                                    $isVuln = TRUE;
                                }
                            } else {
                                $isVuln = TRUE;
                            }
                        }
                    }
                }
            }

            $result['isVuln'] = $isVuln;
        }

        return $result;
    }


    /**
     *
     */
    public function analyse_js_version($regex, $attribute_value,
                                        $vuln_if_smaller, $vuln_array) {
        // check if it contains version
        $version_regex = $regex;
        if (preg_match($version_regex, $attribute_value, $match) === 1) {
            $version = $match[0];

            // version detected and set
            $result['version'] = $version;
        } else {
            // no version number
            $result['version'] = NULL;
        }

        if ($result['version'] !== NULL) {
            $vuln_versions = $vuln_array;
            $isVuln = FALSE;

            // check specific version defined in array
            foreach ($vuln_versions as $vuln) {
                if ($vuln === $result['version']) {
                    $isVuln = TRUE;
                }
            }

            $split_version = explode(".", $result['version']);
            if ((int)$split_version[0] !== NULL) {
                if ((int)$split_version[0] < $vuln_if_smaller[0]) {
                    $isVuln = TRUE;
                } else if ((int)$split_version[0] === 4) {
                    if ((int)$split_version[1] !== NULL) {
                        if ((int)$split_version[1] <= $vuln_if_smaller[1]) {
                            if ((int)$split_version[2] !== NULL) {
                                if ((int)$split_version[2] <= $vuln_if_smaller[2]) {
                                    $isVuln = TRUE;
                                }
                            } else {
                                $isVuln = TRUE;
                            }
                        }
                    }
                }
            }

            $result['isVuln'] = $isVuln;
        }

        return $result;
    }
        

    /**
     * @short: Search for specific CMS indicators
     * Restrictions: 1 Request to host and analyse only DOM
     * CMS indicators:
     * 1) Meta generator: attribute_value
     * @return array
     */
    public function analyse_cms_specific($cms_name, $vuln_if_smaller, $vuln_array,
                                         $attribute_value, $version_regex,
                                         $attribute_names, $indicators,
                                         $default_version, $attribute_whitelist,
                                         $html_regex) {
        $result = array();

        // 1) search in generator/Author meta tags
        if ($attribute_value !== NULL) {
            foreach ($attribute_value as $field => $value) {
                $meta_generators = $this->searcher->in_meta_with_name($field);
                if (!empty($meta_generators)) {
                    /*
                     * Now check for known vulnerabilities
                     * For references check vuln_references in cms_analysis_config.json
                     * Versions < $vuln_if_smaller are vulnerable
                     */
                    // there is a meta with name $field, check if it contains $value
                    foreach ($meta_generators as $mg) {
                        foreach ($mg->attributes as $attribute) {
                            if ($attribute->name === "content") {
                                if (stripos($attribute->value, $value) !== FALSE) {
                                    // CMS detected
                                    $result['cms'] = $cms_name;

                                    $tmp = $this->analyse_cms_version(
                                        $version_regex,
                                        $attribute->value,
                                        $vuln_if_smaller,
                                        $vuln_array);
                                    if (!empty($tmp['version'])) {
                                        $result['version'] = $tmp['version'];
                                    } else {
                                        $result['version'] = NULL;
                                    }

                                    if ($result['version'] === NULL) {
                                        if ($default_version !== NULL) {
                                            $result['version'] = $default_version;
                                        } else {
                                            $result['version'] = NULL;
                                        }
                                    }

                                    if (!empty($tmp['isVuln'])) {
                                        $result['isVuln'] = $tmp['isVuln'];
                                    } else {
                                        $result['isVuln'] = NULL;
                                    }

                                    $result['node'] = $mg;
                                    $result['node_content'] = $attribute->value;

                                    // there was a finding with max entropy                                    
                                    if (isset($result["isVuln"])) {
                                        return $result;
                                    } else if (isset($result["version"])) {
                                        return $result;
                                    }
                                }
                            }
                        }
                    }

                    //return FALSE;
                    /**
                     * return here and not in loop, because there could be meta tags
                     * containing more informations (like versions)
                     */
                      if (isset($result['cms'])) {
                          // there was at least one finding
                          return $result;
                      }
                    
                }
            }
        }

        return FALSE;
    }

    public function analyse_cms_specific_extended($cms_name, $vuln_if_smaller, $vuln_array,
                                                  $attribute_value, $version_regex,
                                                  $attribute_names, $indicators,
                                                  $default_version, $attribute_whitelist,
                                                  $html_regex) {
        $result = array();

        // 2) 3) search indicator in paths
        if ($attribute_names !== NULL) {
            foreach ($attribute_names as $attribute_name) {
                if ($attribute_whitelist !== NULL) {
                    $path_indicator = $this->searcher->in_node_with_attr($attribute_whitelist, $attribute_name);
                } else {
                    $path_indicator = $this->searcher->in_attr($attribute_name);
                }

                if (empty($path_indicator)) {
                    return $result;
                }

                foreach ($path_indicator as $pi) {
                    foreach ($pi->attributes as $attribute) {
                        foreach ($indicators as $indicator) {
                            if (stripos($attribute->value, $indicator) !== FALSE) {
                                $result['cms'] = $cms_name;

                                // probably no version to find here, do not try
                                if ($default_version !== NULL) {
                                    $result['version'] = $default_version;
                                } else {
                                    $result['version'] = NULL;
                                }
                                $result['isVuln'] = NULL;

                                $result['node'] = $pi;
                                $result['node_content'] = $attribute->value;

                                return $result;
                            }
                        }
                    }
                }
            }
            if (isset($result['cms'])) {
                // there was at least one finding
                return $result;
            }
        }

        // 4) search html regex in source
        if ($html_regex !== NULL) {
            foreach ($html_regex as $value) {
                preg_match($value['regex'], $this->source, $search_result);
                if (!empty($search_result)) {
                    $result['cms'] = $cms_name;

                    // probably no version to find here, do not try
                    if ($default_version !== NULL) {
                        $result['version'] = $default_version;
                    } else {
                        $result['version'] = NULL;
                    }
                    $result['isVuln'] = NULL;

                    $result['node'] = $value['node'];
                    $result['node_content'] = $search_result[0];

                    return $result;
                }
            }
        }
    }

    /**
     * TODO: False-Positive = https://www.fietz-medien.de/eshops-groupware/webshop-systeme/xtcommerce-3.04-sp2.1/index.html
     * in meta tag CMS CONTENIDO is defined but scanner finds also wp-content path
     * and as wordpress is tested first it will say it is a wordpress website
     */
    public function analyse_cms($extend=FALSE) {
        $analysis_config = json_decode(
            file_get_contents("01_model/libs/cms_analysis_config.json"), true);
        
        if ($extend) {
            foreach ($analysis_config as $field => $value) {
                $cms = $this->analyse_cms_specific_extended($value['name'],
                                                            $value['vuln_if_smaller'],
                                                            $value['vuln_array'],
                                                            $value['meta'],
                                                            $value['version_regex'],
                                                            $value['attribute_names'],
                                                            $value['indicators'],
                                                            $value['default_version'],
                                                            $value['attribute_whitelist'],
                                                            $value['html_regex']);

                if (isset($cms["cms"])) {
                    return $cms["cms"];
                }
            }
        }

        foreach ($analysis_config as $field => $value) {
            $result = $this->analyse_cms_specific($value['name'],
                                                  $value['vuln_if_smaller'],
                                                  $value['vuln_array'],
                                                  $value['meta'],
                                                  $value['version_regex'],
                                                  $value['attribute_names'],
                                                  $value['indicators'],
                                                  $value['default_version'],
                                                  $value['attribute_whitelist'],
                                                  $value['html_regex']);

            if (!empty($result)) {
                return $result;
            }
        }
    }

    public function analyse_js_specific($name, $tag, $default_version,
                                        $vuln_if_smaller, $vuln_array,
                                        $version_regex) {
        $result = array();
        $nodes = $this->searcher->in_script($name);

        if (empty($nodes)) {
            return FALSE;
        }
        
        foreach ($nodes as $node) {
            foreach ($node->attributes as $attr) {
                if (strpos($attr->value, $name) !== FALSE) {
                    $result["lib"] = $name;

                    $tmp = $this->analyse_js_version(
                        $version_regex,
                        $attr->value,
                        $vuln_if_smaller,
                        $vuln_array);

                    if (!empty($tmp["version"])) {
                        $result["version"] = $tmp["version"];
                    } else {
                        $result["version"] = NULL;
                    }

                    if ($result['version'] === NULL) {
                        if ($default_version !== NULL) {
                            $result['version'] = $default_version;
                        } else {
                            $result['version'] = NULL;
                        }
                    }

                    if (!empty($tmp['isVuln'])) {
                        $result['isVuln'] = $tmp['isVuln'];
                    } else {
                        $result['isVuln'] = NULL;
                    }

                    $result["node"] = $node;
                    $result["node_content"] = $attr->value;

                    if (isset($result["isVuln"])) {
                        return $result;
                    } else if (isset($result["version"])) {
                        return $result;
                    }
                }
            }
        }

        if (isset($result["lib"])) {
            return $result;
        } else {
            return FALSE;
        }
    }

    public function get_worst_finding_js_lib($result) {
        $worst = NULL;
        
        foreach ($result as $finding) {
            if ($finding["isVuln"]) {
                $worst = $finding;
            }
        }
        
        if ($worst === NULL) {
            foreach ($result as $finding) {
                if (!empty($finding["version"])) {
                    $worst = $finding;
                }
            }
        }
        
        if ($worst === NULL) {
            foreach ($result as $finding) {
                if (!empty($finding["lib"])) {
                    $worst = $finding;
                }
            }
        }

        return $worst;
    }
        
    public function analyse_JSLib() {
        $analysis_config = json_decode(
            file_get_contents("01_model/libs/js_analysis_config.json"), true);
        

        foreach ($analysis_config as $field => $value) {
            $result[] = $this->analyse_js_specific($value['name'],
                                                 $value['tag'],
                                                 $value['default_version'],
                                                 $value['vuln_if_smaller'],
                                                 $value['vuln_array'],
                                                 $value['version_regex']);


            if (!empty($result)) {
                return $this->get_worst_finding_js_lib($result);
            }
        }
    }



    /**
     * @short: Detect used Javascript libraries.
     * @algorithm: It will search for libraries only in script tags, so that
     * * false positives are reduced drastically.
     *
     * @return array
     */
    public function analyse_JSLib1($file="./wordfiles/JSLibs.conf") {
        $j = 0;
        $result_ = $result = $version = $isVuln = $lib = array();
        //$lineCount = count(file($file));
        $to_filter = FALSE;

        /* http://domstorm.skepticfx.com/modules?id=529bbe6e125fac0000000003 */
        /* Vulnerable to Selector XSS with class Attribute ('. XSS_VECTOR') */
        /* other: https://www.cvedetails.com/vulnerability-list/vendor_id-6538/Jquery.html */
        /* https://snyk.io/test/npm/jquery/1.12.4?severity=high&severity=medium&severity=low */
        $vuln_jquery = array(
            '2.0.3', '2.0.2', '2.0.1', '2.0.0', '1.10.2', '1.10.1',
            '1.10.0', '1.9.1', '1.9.0', '1.8.3', '1.8.2', '1.8.1', '1.8.0',
            '1.7.2', '1.7.1', '1.7.0', '1.6.4', '1.6.3', '1.6.2', '1.6.1',
            '1.6.0', '1.5.2', '1.5.1', '1.5.0', '1.4.4', '1.4.3', '1.4.2',
            '1.4.1', '1.4.0', '1.3.2', '1.3.1', '1.3.0', '1.2.6', '1.2.3',
            '1.12.0', '3.0.0', '1.12.4', '2.1.4'
        );

        /* https://www.cvedetails.com/vulnerability-list/vendor_id-11858/Netease.html */
        $vuln_netease = array('1.1.2', '1.2.0');

        /**
         * https://www.cvedetails.com/vulnerability-list/vendor_id-7662/
         * Expressionengine.html
         */
        $vuln_expressionengine = array('1.6.6', '1.6.4', '1.2.1');

        $lines = file($file, FILE_IGNORE_NEW_LINES);
        foreach ($lines as $line) {
            $nodes = $this->searcher->in_all($line);
            if (!empty($nodes->length)) {
                foreach ($nodes as $node) {

                    /* Filter Tags */
                    if ($node->nodeName !== "script") {
                        $to_filter = TRUE;
                    }

                    if ($to_filter === FALSE) {
                        $result[] = $node;

                        /* Filter attributes */
                        foreach ($node->attributes as $attr) {
                            if (strpos($attr->value, $line) !== FALSE) {
                                // Get version of Javascript library
                                $tmp   = $this->getVersionNumber($attr->value);
                                $lib[] = $line;

                                if (!empty($tmp)) {
                                    $version[] = $tmp;
                                    $isVuln[]  = FALSE;
                                    $j++;

                                    if ($line === "jquery") {
                                        foreach ($vuln_jquery as $vuln) {
                                            if ($tmp === $vuln) {
                                                $isVuln[$j-1] = TRUE;
                                                break;
                                            }
                                        }
                                    } else if ($line === "netease") {
                                        foreach ($vuln_netease as $vuln) {
                                            if ($tmp === $vuln) {
                                                $isVuln[$j-1] = TRUE;
                                                break;
                                            }
                                        }
                                    } else if (($line === "sitecatalyst") ||
                                               ($line === "omniture")) {
                                        /**
                                         * https://web.nvd.nist.gov/view/vuln/
                                         * detail?vulnId=CVE-2006-6640
                                         */
                                        $isVuln[$j-1] = TRUE;
                                    } else if ($line === "analytics.js") {
                                        /**
                                         * http://www.theregister.co.uk/2008/11/
                                         * 22/google_analytics_as_security_risk/
                                         */
                                        $isVuln[$j-1] = TRUE;
                                    } else if ($line === "marketo") {
                                        /**
                                         * https://www.cvedetails.com/cve/CVE-20
                                         * 14-8379/
                                         */
                                        $isVuln[$j-1] = TRUE;
                                    } else if ($line === "expressionengine") {
                                        foreach ($vuln_expressionengine as $vuln) {
                                            if ($tmp === $vuln) {
                                                $isVuln[$j-1] = TRUE;
                                                break;
                                            }
                                        }
                                    } else if ($line === "dotnetnuke") {
                                        /**
                                         * https://www.cvedetails.com/
                                         * vulnerability-list/vendor_id-2486/
                                         * Dotnetnuke.html
                                         */
                                        $isVuln[$j-1] = TRUE;
                                    } else if ($line === "ektron") {
                                        /**
                                         * https://www.cvedetails.com/
                                         * vulnerability-list/vendor_id-8415/
                                         * Ektron.html
                                         */
                                        $isVuln[$j-1] = TRUE;
                                    } else if ($line === "disqus") {
                                        /**
                                         * https://blog.sucuri.net/2014/06/
                                         * anatomy-of-a-remote-code-execution-bug
                                         * -on-disqus.html
                                         */
                                        $isVuln[$j-1] = TRUE;
                                    } else if ($line === "prototype") {
                                        /**
                                         * https://www.cvedetails.com/
                                         * vulnerability-list/vendor_id-6541/
                                         * Prototypejs.html
                                         */
                                        $isVuln[$j-1] = TRUE;
                                    } else if ($line === "lightbox") {
                                        /**
                                         * https://www.cvedetails.com/
                                         * vulnerability-list/vendor_id-15110/
                                         * product_id-30739/version_id-178428/
                                         * Lightbox-Photo-Gallery-Project-Lightbox
                                         * -Photo-Gallery-1.0.html
                                         */
                                        $isVuln[$j-1] = TRUE;
                                    } else {
                                        $isVuln[$j-1] = "N/A";
                                    }
                                } else {
                                    $version[] = "N/A";
                                    $isVuln[]  = "N/A";
                                }
                            }
                        }
                    } else {
                        $to_filter = FALSE;
                    }
                }
            }
        }

        foreach ($lib as $key => $value) {
            if ($value === "jquery") { // vuln lib found

                if (empty($isVuln[$key])) {
                    continue;
                }

                if ($isVuln[$key] === FALSE) {
                    unset($lib[$key]);
                    unset($isVuln[$key]);
                    unset($version[$key]);
                    unset($result[$key]);

                    $lib = array_values($lib);
                    $isVuln = array_values($isVuln);
                    $version = array_values($version);
                    $result = array_values($result);
                }
            }

            if (empty($version[$key])) {
                continue;
            }

            if ($version[$key] === "N/A") {
                unset($lib[$key]);
                unset($isVuln[$key]);
                unset($version[$key]);
                unset($result[$key]);

                $lib = array_values($lib);
                $isVuln = array_values($isVuln);
                $version = array_values($version);
                $result = array_values($result);
            }
        }

        $result_['nodes']   = $result;
        $result_['version'] = $version;
        $result_['isVuln']  = $isVuln;
        $result_['lib']     = $lib;

        return $result_;
    }


    /**
     * @short: Detect hidden input fields
     * @algorithm: It is searching for hidden input fields, which seem to be
     * * for: usernames/passwords/emails/carts
     *
     * @note: We don't need to search for forms with autocomplete on _and_ are
     * * intented for passwords/usernames/..., because this will output these
     * * anyways.
     * TODO: Which hidden input fields could be also of interest?
     * @return array
     */
    public function analyse_inputs() {
        $result = array();

        /* No need for a file, just search for hidden input fields */
        $line = "hidden";

        $nodes = $this->searcher->in_input($line);
        if (!empty($nodes->length)) {
            //$result = $nodes;
            foreach ($nodes as $node) {
                foreach ($node->attributes as $child) {
                    if (preg_match("/pass|password|passwort|passwd|pw/i",
                                   $child->value) !== 0) {
                        $result[] = $node;
                    } else if (preg_match("/mail|email|e-mail/i",
                                          $child->value) !== 0) {
                        $result[] = $node;
                    } else if (preg_match("/cart|korb|einkauf/i",
                                          $child->value) !== 0) {
                        $result[] = $node;
                    } else if (preg_match("/user|usr|benutzer/i",
                                          $child->value) !== 0) {
                        $result[] = $node;
                    }

                }
            }
        }

        return $result;
    }


    /**
     * @short: Detect interesting comments
     * TODO: reduce false positives (difficult in comments...)+
     * @return array
     */
    public function analyse_comments($file="./wordfiles/comments.conf") {
        $i           = 0;
        $lineCount   = count(file($file));
        $result      = array();
        $uniq_result = array();
        $to_filter   = FALSE;

        while ($i < $lineCount) {
            ++$i;
            $line = getLine($file, $i);
            $line = preg_replace("/\n/", "", $line);

            $nodes = $this->searcher->in_comment($line);
            if (!empty($nodes->length)) {
                foreach ($nodes as $node) {
                    /* Filter Conditional Comments */
                    if (preg_match("/if\s?(lte|lt|gt|gte|[\|\&\!])?\s?IE/",
                                   $node->nodeValue) !== 0) {
                        $to_filter = TRUE;
                    }

                    if ($to_filter === FALSE) {
                        $uniq_result[] = $node->nodeValue;
                    } else {
                        $to_filter = FALSE;
                    }
                }
            }
        }

        /**
         * Suprisingly there are often duplicate comments, just sort those
         * out...
         */
        $uniq_result = array_unique($uniq_result, SORT_LOCALE_STRING);
        $result      = $uniq_result;

        return $result;
    }


    /**
     * @short: Detect all interesting meta tags.
     * @note: The results are not filtered yet. I did not see any reasons to do
     * * so.
     * @return array
     */
    public function analyse_metas($file="./wordfiles/metas.conf") {
        $i         = 0;
        $lineCount = count(file($file));
        $result    = array();

        while ($i < $lineCount) {
            ++$i;
            $line = getLine($file, $i);
            $line = preg_replace("/\n/", "", $line);

            $nodes = $this->searcher->in_meta($line);
            if (!empty($nodes->length)) {
                $result[] = $nodes;
            }
        }

        return $result;
    }


    /**
     * @short: Find all given paths of this host.
     * @var url: Only looks for paths of this host.
     * @var attributes_search: Holds attributes which are able to contain paths.
     * @algorithm: There is a limited count of options, where paths can be
     * placed. Just look for those, which are defined with $attributes_search.
     * @return array
     */
    public function find_path($url) {
        $result = array();
        $host   = parse_url($url, PHP_URL_HOST);

        $attributes_search = array(
            "href",
            "src",
            "data",
            "poster",
            "codebase"
        );

        foreach ($attributes_search as $line) {
            $nodes = $this->searcher->in_attr($line);

            if (!empty($nodes[0])) {
                foreach ($nodes as $node) {
                    foreach ($node->attributes as $attribute) {
                        if ($attribute->name === $line) {
                            $path      = parse_url($attribute->value, PHP_URL_PATH);
                            $host_attr = parse_url($attribute->value, PHP_URL_HOST);

                            if (($host === $host_attr) || (empty($host_attr))) {
                                if ($path !== "/") {
                                    $result[] = $path;
                                }
                            }
                        }
                    }
                }
            }
        }
        /* Duplicate paths are not relevant. */
        $result = array_unique($result, SORT_LOCALE_STRING);

        return $result;
    }

    /**
     * @short: Searches for git files.
     * TODO: Search for SVN.
     * @return array
     */
    public function find_SVN_GIT($source) {
        $regex = '`(?:(?:ssh|rsync|git|https?|file)://)?[a-z0-9.@:/~]+\\.git/?`i';

        preg_match_all($regex, $source, $result);

        $result = array_unique($result[0], SORT_REGULAR);

        return $result;
    }

    /**
     * @short: Searches SQL Query
     * TODO: Search for other than MySQL.
     * Too many false positives!!
     * @return array
     */
    public function find_SQLQuery($source) {
        /* This Regex will catch most MySQL queries */
        $regex  = "/(SELECT|UPDATE|ALTER|CREATE|DROP|RENAME|TRUNCATE|INSERT|DELETE)";
        $regex .= "?\s[A-Z0-9_-]*(TABLE|DATABASE|SCHEMA|FROM|INTO|SET)\s*[A-Z0-9_\-=]*/i";

        preg_match_all($regex, $source, $result);

        $result = array_unique($result[0], SORT_REGULAR);

        return $result;
    }

    /**
     * @short: Searches Creditcards
     * @credits: Regex from (edited): w3af; Author: Alexander Berezhnoy
     * Test on:
     * https://www.paypalobjects.com/en_US/vhelp/paypalmanager_help/credit_card_numbers.htm
     * TODO: Build up a better regex.
     * @return array
     */
    public function find_CC($source) {
        /* This Regex won't find all types of CCs */
        $regex  = "/(([^\w+]|\s)\d{4}[- ]?(\d{4}[- ]?\d{4}|";
        $regex .= "\d{6})[- ]?(\d{5}|\d{4})([^\w+]|\s))/";

        preg_match_all($regex, $source, $result);

        $result = array_unique($result[0], SORT_REGULAR);

        $tmp = array();
        foreach ($result as $r) {
            $tmp[] = substr($r, 1, -1);
        }

        return $tmp;
    }

    /**
     * @short: Searches for IPs.
     * @algorithm: The regex will match all IPs from 0.0.0.0 to
     * * 255.255.255.255. Before adding the found IPs it will check whether they
     * * are valid.
     * @return array
     */
    public function find_IP($source) {
        $regex  = "/\b(([1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)(([0-9]|";
        $regex .= "[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.) {2}([0-9]|";
        $regex .= "[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b/";

        preg_match_all($regex, $source, $result);

        /* Duplicate IPs are not relevant. */
        $result = array_unique($result[0], SORT_REGULAR);

        $IP = array();

        foreach ($result as $ips) {
            /* Are the found IPs really valid? */
            if (filter_var($ips, FILTER_VALIDATE_IP)) {
                $IP[] = $ips;
            }
        }

        return $IP;
    }

    public function getDOM() {
        return $this->searcher->getDOM();
    }
}

?>
