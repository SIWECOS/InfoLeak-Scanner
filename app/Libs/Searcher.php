<?php

namespace App\Libs;

class Searcher {
    private $xpath;
    private $verbose = false;

    public function __construct($source){
        libxml_use_internal_errors(true);

        /* SETUP DOM */
        try {
            $doc = new \DOMDocument();
            $doc->loadHTML($source);
        } catch(\Exception $e) {
            if ($this->verbose) {
                \Log::info("Searcher was provided with a empty DOM");
                \Log::warning("Exception: " . e);
            }

            $source = "<html><head></head><body></body></html>";

            $doc = new \DOMDocument();
            $doc->loadHTML($source);
        } finally {
            /* SETUP XPath Object */
            $this->xpath = new \DOMXPath($doc);
        }
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
    public function in_script($word){
        $nodes = $this->xpath_search("//script[@*[contains(., '" . $word . "')]]");

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
