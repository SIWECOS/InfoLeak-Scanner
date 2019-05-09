<?php

namespace App\Libs;

class Messages {
    private $messages_file = __DIR__ . "/messages.xml";
    private $messages;


    /**
     * messages.xml structure:
     *
     * <messages>
     *  <message id="0">
     *    <name>test</name>
     *    <type>comment</type>
     *    <content>this is a comment</content>
     *  </message>
     * </messages>
     */
    public function __construct() {
        if (file_exists($this->messages_file)) {
            $this->messages = simplexml_load_file($this->messages_file);
        } else {
            echo 'Error (Class: Messages; __construct): Failed to open '
                . $this->messages_file;
        }
    }


    /**
     * Entries in messages.xml are listed with id attributes.
     * Select message with a given id and optionally add note to message.
     */
    public function getMessageById($id, $note="") {
        $node = $this->messages->xpath("//message[@id=" . intval($id) . "]");

        if ($node) {
            $content = $node[0]->content;

            if ($note === "") {
                return $content[0] . ".";
            } else {
                return $content[0] . " (" . strval($note) . ").";
            }
        }
    }

    /**
     * Entries in messages.xml are listed with id attributes.
     * Select message with a given id and return its name (placeholder)
     */
    public function getNameById($id) {
        $node = $this->messages->xpath("//message[@id=" . intval($id) . "]/name");

        if ($node) {
            return $node;
        }
    }


    /**
     * Select message by its name and optionally add note to message.
     */
    public function getMessageByName($name, $note="") {
        $node = $this->messages->xpath("//message/name[. ='"
                                       . strval($name)
                                       . "']/following-sibling::content")[0];
        if ($node) {
            if ($note === "") {
                return $node[0] . ".";
            } else {
                return $node[0] . " (" . strval($note) . ").";
            }
        }
    }
}

?>
