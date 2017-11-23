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

include '00_control/control.php';
include '01_model/model.php';
include '02_view/view.php';


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

    /* Exit here if something went wrong/was disallowed. */
    if ($controller->to_analyse === FALSE) {
        return;
    }

    /**
     * The performance analysis will only be made over the model.
     * The model is independent from bandwith, latency etc.
     * Also the model is the only object where the data is actually processed.
     * The model is aware of the controller.
     */
    //$before = microtime(TRUE);
    $model = new Model($controller);
    //$after = microtime(TRUE);

    /*
     * The view will generate the output. It gets all data from model, which are
     * mostly HTML nodes. It will iterate through these and generate an output
     * this way.
     * The view is aware of the model and the controller.
     */
    $view = new View($model, $controller);

    //echo "<br/><br/><p>Done in " . ($after-$before) . " seconds.</p>\r\n";
}
?>
