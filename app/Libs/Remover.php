<?php

namespace App\Libs;

class Remover {
    private $xpath;
    private $DOM;
    private $source;
    private $verbose = false;

    public function __construct($source){
        libxml_use_internal_errors(true);

        $this->source = $source;
        $this->resetXPath();
    }


    /**
     * Create new DOMXPath with $this->source
     */
    public function resetXPath() {

        try {
            /* SETUP DOM */
            $doc = new \DOMDocument();
            $doc->loadHTML($this->source);

            $this->DOM = $doc;
        } catch(\Exception $e) {
            if ($this->verbose) {
                \Log::info("Remove was provided with a empty DOM");
                \Log::warning("Exception: " . e);
            }

            $this->source = "<html><head></head><body></body></html>";

            $doc = new \DOMDocument();
            $doc->loadHTML($this->source);

            $this->DOM = $doc;
        } finally {
            /* SETUP XPath Object */
            $this->xpath = new \DOMXPath($doc);
        }
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
     * Remove global data attribute (data-*)
     */
    public function removeData($source) {
        $query = $this->xpath->query("//*[@*[starts-with(name(), 'data-')]]");

        foreach ($query as $node) {
            $node->parentNode->removeChild($node);
        }

        $this->source = $this->DOM->saveHTML();

        return $this->source;
    }

    /**
     * TODO: Not working correctly yet
     */
    public function removeKISSY($source) {
        $query = $this->xpath->query("//div/@id[starts-with(name(), 'J_')]");

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
