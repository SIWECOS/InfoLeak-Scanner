<?php

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
