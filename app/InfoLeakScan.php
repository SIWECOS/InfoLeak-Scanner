<?php

namespace App;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use App\Libs\Analyser;
use App\Libs\View;


class InfoLeakScan {

    protected $version;
    protected $url;
    protected $body = null;
    protected $dangerlevel;
    protected $callbackurls;
    protected $useragent;
    protected $client;
    private $verbose = false;

    protected $result;

    public function __construct(string $url, int $dangerlevel,
                                array $callbackurls, string $useragent) {
        $this->version = file_get_contents(base_path('VERSION'));

        $this->url = $url;
        $this->dangerlevel = $dangerlevel;
        $this->callbackurls = $callbackurls;
        $this->useragent = $useragent;

        $this->client = new Client([
            ['defaults' => [ 'exceptions' => false ]],
            ['http_errors' => true],
            'timeout' => 50, // Response timeout
            'connect_timeout' => 50, // Connection timeout
            'headers'         => [
                'User-Agent'  => $useragent,
            ]
        ]);
    }

    public function scan() {
        $view = new View(file_get_contents(base_path('VERSION')));

        try {
            $this->url = $this->punycodeUrl($this->addHTTP($this->url));

            $this->body = $this->client->get($this->url)->getBody();
        } catch (\Exception $e) {
            \Log::warning('Could not connect to: ' . $url);

            if ($this->verbose)
                \Log::warning('Guzzle error: ' . $e);

            $view = $view->printError($e->getMessage(), get_class($e));

            $this->result = json_encode($view,
                                        JSON_PRETTY_PRINT |
                                        JSON_UNESCAPED_UNICODE |
                                        JSON_UNESCAPED_SLASHES);

            if (count($this->callbackurls)) {
                $this->notifyCallbacks();
            }

            \Log::warning('Error reporting done: ' . $this->url);

            return $this->result;
        }

        $analyser = new Analyser($this->url, $this->body);

        $email = $analyser->find_email($this->body);
        $cms = $analyser->analyse_cms();
        $plugins = null;
        if (!empty($cms['cms'])) {
            $plugins = $analyser->analyse_plugins($cms['cms']);
        }
        $jslib = $analyser->analyse_JSLib();
        $phone_number = $analyser->find_phoneNumber($this->body);


        $view = $view->printJSON($cms, $email,$plugins,
                                 $jslib, $phone_number);

        $this->result = json_encode($view,
                                    JSON_PRETTY_PRINT |
                                    JSON_UNESCAPED_UNICODE |
                                    JSON_UNESCAPED_SLASHES);


        if (count($this->callbackurls)) {
            $this->notifyCallbacks();
        }

        \Log::info('JOB DONE: ' . $this->url);

        return $this->result;
    }


    /**
     * @short: Add HTTP scheme to the URL.
     * @var url: The URL which will get the scheme added
     * @algorithm: Is the scheme specified? If not add it, else leave it as it
     * * is.
     * @return string
     */
    private function addHTTP($url, $scheme = 'http://') {
        return parse_url($url, PHP_URL_SCHEME) === null ? $scheme . $url : $url;
    }

    /**
     * Returns the Punycode encoded URL for a given URL.
     *
     * @param string $url URL to encode
     *
     * @return string Punycode-Encoded URL.
     * @author https://github.com/Lednerb
     */
    public function punycodeUrl($url) {
        $parsed_url = parse_url($url);
        $scheme = isset($parsed_url['scheme']) ? $parsed_url['scheme'].'://' : '';
        $host = isset($parsed_url['host']) ? idn_to_ascii($parsed_url['host'],
                                                          IDNA_NONTRANSITIONAL_TO_ASCII,
                                                          INTL_IDNA_VARIANT_UTS46) : '';
        $port = isset($parsed_url['port']) ? ':'.$parsed_url['port'] : '';
        $user = isset($parsed_url['user']) ? $parsed_url['user'] : '';
        $pass = isset($parsed_url['pass']) ? ':'.$parsed_url['pass'] : '';
        $pass = ($user || $pass) ? "$pass@" : '';
        $path = isset($parsed_url['path']) ? $parsed_url['path'] : '';
        $query = isset($parsed_url['query']) ? '?'.$parsed_url['query'] : '';

        return "$scheme$user$pass$host$port$path$query";
    }

    protected function notifyCallbacks(): void
    {
        foreach ($this->callbackurls as $url) {
            Log::info('Callback to: ' . $url);

            try {
                $this->client->post($url, [
                    'headers'     => ['Content-type' => 'application/json'],
                    'http_errors' => false,
                    'timeout'     => 60,
                    'json'        => json_decode($this->result)
                ]);
            } catch (\Exception $e) {
                Log::warning('Callback error (url): ' . $url);
            }

            Log::info('Finished callback for ' . $url);
        }
    }
}
?>
