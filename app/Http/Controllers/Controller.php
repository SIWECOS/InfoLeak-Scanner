<?php

/**
 *   Automatic Detection of Information Leakage Vulnerabilities in
 *   Web Applications.
 *
 *   Copyright (C) 2015-2019 Ruhr University Bochum
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

namespace App\Http\Controllers;

use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use App\Http\Requests\ScanStartRequest;
use App\InfoLeakScan;
use App\Jobs\LeakJob;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    public function start(ScanStartRequest $request) {
        if ($request->get('callbackurls')) {
            LeakJob::dispatch($request->validated());

            return "OK";
        }

        // NOTE(ya): Default user agent.
        $agent  = file_get_contents(app_path() . "/Libs/default_UA");

        $scan = new InfoLeakScan(
            $request->get('url'),
            0,
            $request->get('callbackurls', []),
            $request->get('userAgent', $agent)
        );

        return response($scan->scan(), 200)->header('Content-Type', 'application/json; charset=utf-8');
    }
}
