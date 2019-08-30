<?php

namespace App\Http\Controllers;

use App\Http\Requests\ScanStartRequest;
use Illuminate\Http\Request;
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
            $request->get('userAgent', config('scanner.user_agent'))
        );

        return response($scan->scan(), 200)
            ->header('Content-Type', 'application/json; charset=utf-8')
            ->header('User-Agent', $request->get('userAgent', config('scanner.user_agent')));
    }

    public function reflect(ScanStartRequest $request) {
        if (count($request->json()->all())) {
            return $request->json()->all();
        }
        return "[-] Could not reflect";
    }
}
