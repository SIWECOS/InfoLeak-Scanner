<?php

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    echo "Testing the receive of POST data using callbacks";
    
    $data = json_decode(file_get_contents("php://input"));

    /* Exit if JSON can not be decoded. */
    if ($data === NULL) {
        echo "$DATA === NULL";
        return;
    }

    file_put_contents("/tmp/callbackPostData.txt", print_r($data, true) . $_SERVER['HTTP_USER_AGENT'] . "\n\n");
    
    return $data;
}

?>