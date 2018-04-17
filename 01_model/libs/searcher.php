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

class Searcher{
    private $xpath;
    private $DOM;     /* $DOM is not used. */

    public function __construct($source){
        libxml_use_internal_errors(true);
        /* SETUP DOM */
        $doc = new DOMDocument();
        $doc->loadHTML($source);

        $this->DOM = $doc;

        /* SETUP XPath Object */
        $this->xpath = new DOMXPath($doc);
    }


    /**
     * @short Return DOM
     * @return DOMDocument
     */
    public function getDom(){
        return $this->DOM;
    }

    /**
     * @short Search $word attribute containing $content in the given DOM (case sensitive).
     * @return node
     */
    public function in_attr_contains($word, $content){
        $nodes = $this->xpath_search("//*[@" . $word . "[contains(.," . $content . ")]]");

        return $nodes;
    }
    
    /**
     * @short Search $word attribute in the given DOM (case sensitive).
     * @return node
     */
    public function in_attr($word){
        $nodes = $this->xpath_search("//*[@" . $word . "]");

        return $nodes;
    }

    public function in_node_with_attr($node, $attr){
        $nodes = $this->xpath_search("//" . $node . "[@" . $attr . "]");

        return $nodes;
    }    

    /**
     * @short Search $word in all attributes of the given DOM (case insensitive).
     * @return node
     */
    public function in_all_caseInsensitive($word){
        $nodes = $this->xpath_search("//*[@*[contains(., '" . $word . "')]]");

        return $nodes;
    }

    /**
     * @return node
     */
    public function in_all($word){
        //$nodes = $this->xpath_search("//*[@*[contains(., '" . $word . "')]]");
        $nodes = $this->xpath_search("//*[@*[contains(translate(., 'ABCDEFGHJIKLMNOPQRSTUVWXYZ', 'abcdefghjiklmnopqrstuvwxyz'), '" . $word . "')]]");

        return $nodes;
    }

    /**
     * @return node
     */
    public function in_input($word){
        $nodes = $this->xpath_search("//input[@*[contains(., '" . $word . "')]]");

        return $nodes;
    }

    /**
     * @short Search $word in all meta tags of the given DOM
     * @return node
     */
    public function in_meta($word){
        $nodes = $this->xpath_search("//meta[@*[contains(., '" . $word . "')]]");

        return $nodes;
    }

    /**
     * @short Search $word in all meta tags of the given DOM
     * @return node
     */
    public function in_meta_with_name($name){
        $nodes = $this->xpath_search("//meta[@name='" . $name . "']");

        return $nodes;
    }
    
    /**
     * @short Search $word in all a-tags of the given DOM
     * @return node
     */
    public function in_a($word){
        $nodes = $this->xpath_search("//a[@*[contains(., '" . $word . "')]]");

        return $nodes;
    }

    /**
     * @short Search $word in all comments
     * @return node
     */
    public function in_comment($word){
        $nodes = $this->xpath_search("//comment()[contains(., '" . $word . "')]");

        return $nodes;
    }

    /**
     * @short Search via XPath through the DOM with the given $query
     * @var xpath DOMXPath Object
     * @var query XPath query, which will be used for the DOMXPath Object
     * @return node
     */
    public function xpath_search($query){
        $xpath = $this->xpath;
        $nodes = $xpath->query($query);

        if($nodes->length)
            return $nodes;
        else
            return NULL; /* Query result is empty */
    }
}

?>