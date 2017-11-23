<?php

/**
 *   Automatic Detection of Information Leakage Vulnerabilities in
 *   Web Applications.
 *
 *   Copyright (C) 2015-2016 Yakup Ates <Yakup.Ates@rub.de>
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