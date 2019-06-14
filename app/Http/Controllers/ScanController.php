<?php

namespace App\Http\Controllers;

use App\Http\Requests\ScanStartRequest;
use App\InfoLeakScan;
use App\Jobs\LeakJob;

class ScanController extends Controller
{
    public function start(ScanStartRequest $request) {
        if ($request->get('callbackurls')) {
            LeakJob::dispatch($request->validated());

            return "OK";
        }

        $scan = new InfoLeakScan(
            $request->get('url'),
            0,
            $request->get('callbackurls', []),
            $request->get('userAgent', \Config::get('scanner.user_agent'))
        );

        return response($scan->scan(), 200)
            ->header('Content-Type', 'application/json; charset=utf-8')
            ->header('User-Agent', $request->get('userAgent', \Config::get('scanner.user_agent')));
    }
    }
}
