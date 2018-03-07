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

class Remover {
    private $xpath;
    private $DOM;
    private $source;

    public function __construct($source){
        libxml_use_internal_errors(true);

        $this->source = $source;
        $this->resetXPath();
    }


    /**
     * Create new DOMXPath with $this->source
     */
    public function resetXPath() {
        /* SETUP DOM */
        $doc = new DOMDocument();
        $doc->loadHTML($this->source);

        $this->DOM = $doc;

        /* SETUP XPath Object */
        $this->xpath = new DOMXPath($doc);
    }


    /**
     * Remove all occurences of a node in the given DOM ($source)
     */
    public function removeNode($source, $nodeName) {
        $query = $this->xpath->query('//' . $nodeName);

        foreach ($query as $node) {
            $node->parentNode->removeChild($node);
        }

        $this->source = $this->DOM->saveHTML();
        //$this->resetXPath();
        return $this->source;
    }

    /**
     * TODO: Not working correctly yet
     */
    public function removeKISSY($source) {
        $query = $this->xpath->query("//div[contains(@id, 'J_defaultData')]");
        //$query = $this->xpath->query("//div/@id[starts-with(text(), 'J_')]");

        foreach ($query as $node) {
            $node->parentNode->removeChild($node);
        }

        $this->source = $this->DOM->saveHTML();

        return $this->source;
    }

    /**
     * Remove all events in the given DOM ($source)
     */
    public function removeEvents($source) {
        $query = $this->xpath->query("//*/@*[starts-with(name(), 'on')]");

        foreach ($query as $node) {
            $node->ownerElement->removeAttributeNode($node);
        }

        $this->source = $this->DOM->saveHTML();
        //$this->resetXPath();
        return $this->source;
    }


    /**
     * Remove all occurences of an attribute in the given DOM ($source)
     */
    public function removeAttribute($source, $attributeName) {
        $query = $this->xpath->query('//*[@' . $attributeName . ']');

        foreach ($query as $node) {
            $node->removeAttribute($attributeName);
        }

        $this->source = $this->DOM->saveHTML();
        //$this->resetXPath();
        return $this->source;
    }

    /**
     * Remove all attributes in the given DOM ($source)
     */
    public function removeAllAttribute($source, $nodeName) {
        $query = $this->xpath->query('//' . $nodeName);

        foreach ($query as $node) {
            foreach ($node->attributes as $a) {
                //$node->removeAttribute($a->name);
            }
        }

        $this->source = $this->DOM->saveHTML();

        return $this->source;
    }


    /**
     * Remove all comments in the given DOM ($source)
     */
    public function removeComments($source) {
        $query = $this->xpath->query('//comment()');

        foreach ($query as $node) {
            $node->parentNode->removeChild($node);
        }

        $this->source = $this->DOM->saveHTML();
        //$this->resetXPath();
        return $this->source;
    }
}

?>