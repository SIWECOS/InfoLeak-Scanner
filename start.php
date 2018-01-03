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


include '00_control/control.php';
include '01_model/model.php';
include '02_view/view.php';


if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $messages = new Messages();
    $data = json_decode(file_get_contents("php://input"));

    /* Exit if JSON can not be decoded. */
    if ($data === NULL) {
        echo $messages->getMessageByName('JSON_DECODE_ERROR');
        return;
    }

    $controller = new Control($data->url);
    $controller->setDangerLevel($data->dangerLevel);
    $controller->setCallbackurls($data->callbackurls);

    $model = new Model($controller);

    $view = new View($model, $controller, "POST");
} else if ($_SERVER['REQUEST_METHOD'] == "GET") {
    if (!isset($_GET['url']) || empty($_GET['url'])) {
        /**
         * No URL is set or given. The client probably just entered the site.
         * Here we set the starting state.
         */
        return;
    } else {
        /**
         * The controller gets the input data by the user.
         * The controller decides whether the URL is valid and whether the source
         * code will be analysed
         */
        $controller = new Control($_GET['url']);

        $model = new Model($controller);

        $view = new View($model, $controller, "GET");
    }
}

?>