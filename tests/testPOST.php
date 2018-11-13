<?php

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    echo "I am testPOST.php";

    $data = json_decode(file_get_contents("php://input"));

    /* Exit if JSON can not be decoded. */
    if ($data === NULL) {
        echo "$DATA === NULL";
        return;
    }

    //file_put_contents("/tmp/testGettingPostParameters.txt", "I got the following:\r\n");
    file_put_contents("/tmp/testGettingPostParameters.txt", print_r($data, true));
    
    return $data;
}

?>
