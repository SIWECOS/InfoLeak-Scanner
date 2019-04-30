<?php

/**
 *   Automatic Detection of Information Leakage Vulnerabilities in
 *   Web Applications.
 *
 *   Copyright (C) 2015-2019 Ruhr University Bochum
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

namespace App\Libs;

//ini_set('max_execution_time', 300);
error_reporting(E_ERROR);

use App\Libs\Searcher;
use App\Libs\Remover;

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
        $remover = new Remover($source);
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
                          "progress", "time", "area", "img", "circle");
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

        $src_array = explode("\n", $source);
        $rev_array = array_reverse($src_array);
        $source = implode("\n", $rev_array);

        $result = array();
        $phoneNumberUtil = \libphonenumber\PhoneNumberUtil::getInstance();

        $phoneNumberMatcher = $phoneNumberUtil->findNumbers($source,
                                                            $nation,
                                                            null,
                                                            $maxTries = 3000);
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
                    $date[0] = intval($date[0]);
                    $date[1] = intval($date[1]);
                    $date[2] = intval($date[2]);

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
        $toRemove = array("script", "a");
        foreach ($toRemove as $node) {
            $source = $remover->removeNode($this->source, $node);
        }
        $searcher = new Searcher($source);

        $file          = NULL;
        $vulnCheckSite = NULL;

        /* We can only look for plugins if we know the CMS*/
        if (!empty($CMS)) {
            switch ($CMS) {
            case "wordpress":
            case "wp-content":
                $file = app_path() . "/Libs/wordfiles/Plugins/WPPlugins.conf";
                //$vulnCheckSite = "https://wpvulndb.com/search?utf8=TRUE&text=";
                break;
            case "drupal":
                $file = app_path() . "/Libs/wordfiles/Plugins/DrupPlugins.conf";
                break;
            }

            if ($file !== NULL) {
                $plugins        = array();
                $vulnCheck_list = array();
                $result         = array(
                    "result" => NULL,
                    "version" => NULL,
                    "plugin_name" => NULL,
                    "attrName" => NULL
                );
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
                    $nodes = $searcher->in_all_caseInsensitive($line);

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
                                        $vuln_file = app_path() . "/Libs/wordfiles/Plugins/WPvulnDB/" . $line . ".conf";

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
     * @return array
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
            if (array_key_exists(0,$split_version)) {
                if ((int)$split_version[0] < $vuln_if_smaller[0]) {
                    $isVuln = TRUE;
                } else if ((int)$split_version[0] === 4) {
                    if (array_key_exists(1,$split_version)) {
                        if ((int)$split_version[1] <= $vuln_if_smaller[1]) {
                            if (array_key_exists(2,$split_version)) {
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
     * @return array
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

                $url_attributes = array('action', 'cite', 'classid', 'codebase',
                                        'data', 'href', 'longdesc', 'profile',
                                        'src', 'usemap', 'background', 'formaction',
                                        'icon', 'manifest', 'poster', 'srcset');

                foreach ($path_indicator as $pi) {
                    foreach ($pi->attributes as $attribute) {

                        foreach ($url_attributes as $ua) {
                            // indicator is a url, compare domain for equality
                            if ($attribute_name === $ua) {
                                $host_compare = $this->compare_hosts($this->url,
                                                                     $attribute->value);
                                if ($host_compare) {
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
     *
     */
    public function compare_hosts($host1, $host2) {
        $h1 = parse_url($host1, PHP_URL_HOST);
        $h2 = parse_url($host2, PHP_URL_HOST);

        return $h1 === $h2 ? TRUE : FALSE;
    }

    /**
     * TODO: False-Positive = https://www.fietz-medien.de/eshops-groupware/webshop-systeme/xtcommerce-3.04-sp2.1/index.html
     * in meta tag CMS CONTENIDO is defined but scanner finds also wp-content path
     * and as wordpress is tested first it will say it is a wordpress website
     */
    public function analyse_cms($extend=TRUE) {
        $analysis_config = json_decode(
            file_get_contents(app_path() . "/Libs/cms_analysis_config.json"), true);


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
                    return $cms;
                }
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
            file_get_contents(app_path() . "/Libs/js_analysis_config.json"), true);


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
}

?>
