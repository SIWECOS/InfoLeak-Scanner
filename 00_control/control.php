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

class Control{
    public $to_analyse = TRUE;

    private $messages;
    private $url;       /* controlled by client */
    private $source;    /* controlled by website */
    private $header;    /* controlled by website */

    private $dangerLevel; /* not used */
    private $callbackurls = array();
    private $scannerHasError = FALSE;
    private $scannerErrorMessage = NULL;

    /**
     * Set this manually to filter local IP addresses!
     */
    private $bcast; // = "192.168.0.255";
    private $smask; // = "255.255.255.0";

    public function __construct($url) {
        $this->messages = new Messages();
        $this->url = $url;
        $this->url = $this->checkURL($this->url);

        if ($this->url !== FALSE) {
            if ($this->checkRedir() === TRUE) {
                /* URL seems to be OK. Set source code. */
                $return_code = $this->setSource();
                if ($return_code === 28) { // timeout occured
                    $this->to_analyse = FALSE;
                    // error message is set in setSource()
                    $this->setScannerHasError(TRUE);
                    return NULL;
                }
            }
        } else {
            $this->to_analyse = FALSE;
            $this->setScannerHasError(TRUE); /* redundant */
            return NULL;
        }

        /**
         * If the URL was valid but the source code is empty there is nothing to
         * analyse.
         */
        if (empty($this->source)) {
            $this->setScannerErrorMessage(16, array('domain' => $this->url));
            $this->to_analyse = FALSE;
            $this->setScannerHasError(TRUE);
            return NULL;
        }
    }

    /**
     * Function to set the scanners error message.
     */
    public function setScannerErrorMessage($errorMessage) {
        if (is_string($errorMessage)) {
            $this->scannerErrorMessage = $errorMessage;
        }
    }

    /**
     * Function to check if the scanner had an error.
     */
    public function getScannerErrorMessage() {
        return $this->scannerErrorMessage;
    }


    /**
     * Function to indicate that the scanner had an error.
     */
    public function setScannerHasError($hasError=FALSE) {
        if (is_bool($hasError)) {
            $this->scannerHasError = $hasError;
        }
    }

    /**
     * Function to check if the scanner had an error.
     */
    public function getScannerHasError() {
        return $this->scannerHasError;
    }

    /**
     * Function to set dangerLevel
     * NOTE: dangerLevel is not used for now.
     */
    public function setDangerLevel($dangerlevel) {
        if (is_int($dangerlevel)) {
            $this->dangerLevel = $dangerlevel;
        }
    }

    /**
     * Function to set callbackurls
     */
    public function setCallbackurls($callbackurls) {
        $this->callbackurls = $callbackurls;
    }

    /**
     * Function to access dangerLevel
     * NOTE: dangerLevel is not used for now.
     */
    public function getDangerLevel() {
        return $this->dangerLevel;
    }

    /**
     * Function to access callbackurls
     */
    public function getCallbackurls() {
        return $this->callbackurls;
    }

    /**
     * Function to access the private variable $url
     */
    public function getURL() {
        return $this->url;
    }

    /**
     * Function to access the private variable $source
     */
    public function getSource() {
        return $this->source;
    }

    /**
     * @short Get source code of given URL.
     * @var options Defines settings for the cURL connection
     * @var con The cURL connection
     * @algorithm Connects to the global variable $url. Gets content of the
     * * website. Saves content to the global variable $source.
     * @return 0
     */
    private function setSource() {
        $con = curl_init($this->url);

        $user_agent  = "Mozilla/5.0 (Windows; U; Windows NT ";
        $user_agent .= "5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1";

        $options = array(
            CURLOPT_HEADER          => false,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_FOLLOWLOCATION  => true,
            CURLOPT_AUTOREFERER     => true,
            CURLOPT_SSL_VERIFYPEER  => false,
            CURLOPT_USERAGENT       => $user_agent,
            CURLOPT_CONNECTTIMEOUT  => 10,
            CURLOPT_TIMEOUT         => 10
        );

        /* Use settings defined in $options for the connection */
        curl_setopt_array($con, $options);
        /* Save content */
        $this->source = curl_exec($con);

        $curl_errno = curl_errno($con);
        if ($curl_errno === 28) {
            $this->setScannerErrorMessage
                ($this->messages->getMessageByName('NOT_REACHABLE'));
            $this->setScannerHasError(TRUE);

            curl_close($con);
            return 28; // timeout
        }

        curl_close($con);

        return 0;
    }

    /**
     * @short Do not allow redirects to foreign hosts.
     * @var url_host Defines the host
     * @var redir_host Holds destination host of the redirect
     * @algorithm Check whether there is a redirect. If there is a redirect,
     * * check its destination. Do only allow destinations which point to the same
     * * host.
     * @return boolean
     */
    private function checkRedir() {
        $data = $this->header[0];
        $info = $this->header[1];
        $header = substr($data, 0, $info['header_size']);
        if ($info['http_code']>=300 && $info['http_code']<=308) {
            preg_match("!\r\n(?:Location|URI): *(.*?) *\r\n!", $header, $redir);

            if (!empty($redir[1])) {
                $tmp = $this->checkURL($redir[1]);
                if ($tmp !== FALSE) {
                    $redir_host = parse_url($this->checkURL($redir[1]));
                } else {
                    $this->setScannerErrorMessage
                        ($this->messages->getMessageByName('REDIRECT_ERROR'));
                    $this->setScannerHasError(TRUE);
                    return FALSE;
                }

                //$redir_host = parse_url($redir[1]);
                $url_host = parse_url($this->url);

                if (empty($redir_host['host']) || empty($url_host['host']))
                    return TRUE;

                if ($url_host['host'] === $redir_host['host']) {
                    return TRUE;
                } else {
                    $this->setScannerHasError(TRUE);
                    return FALSE;
                }
            } else {
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    /**
     * @short Returns header fields.
     * @var result Contains header fields
     * @var con The cURL connection
     * @var options Defines settings for the cURL connection
     * @return string
     */
    private function setHeader($url) {
        $con = curl_init($this->url);

        $user_agent  = "Mozilla/5.0 (Windows; U; Windows NT ";
        $user_agent .= "5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1";

        $options = array(
            CURLOPT_HEADER         => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT      => $user_agent,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 10
        );

        curl_setopt_array($con, $options);
        $data = curl_exec($con);
        $info = curl_getinfo($con);

        $curl_errno = curl_errno($con);
        if ($curl_errno === 28) {
            $this->setScannerErrorMessage
                ($this->messages->getMessageByName('NOT_REACHABLE'));
            $this->setScannerHasError(TRUE);

            curl_close($con);
            return 28; // timeout
        }

        $result = array(
            '0' => $data,
            '1' => $info
        );
        $this->header = $result;

        curl_close($con);
        return $result;
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

    /*
     * @short: Validate the given URL.
     * @var url: The URL which is going to be analyzed
     * @var url_head: Contains respone headers
     * @algorithm: Did the user specify the protocol?
     * * If not, do it with 'http://'.
     * * Are all characters within the URL valid?
     * * Does the URL exist? Does it respond?
     * * Check the HTTP status code - if it's 404 the given address
     * * probably does not exist -> exit.
     * * Is a local/localhost address given? If so, exit.
     * * Is a port other than 80 (HTTP) or 443 (HTTPS) specified? If so, exit.
     * * Do not allow any username/passwords within the given url.
     *
     * IMPORTANT: $url may be edited.
     * @return boolean
     */
    private function checkURL($url) {
        if (!empty($url)) {
            /* Does the URL have illegal characters? */
            $url = filter_var($url, FILTER_SANITIZE_URL);

            /* Protocol specified? */
            $url = $this->addHTTP($url);

            /* Is the URL valid? */
            if ((filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_HOST_REQUIRED) === FALSE)) {
                $this->setScannerErrorMessage
                    ($this->messages->getMessageByName('NO_VALID_URL'));
                $this->setScannerHasError(TRUE);
                return FALSE;
            } else {
                $url_tmp = parse_url($url);

                if (isset($url_tmp['host'])) {
                    if (($url_tmp['host'] === '127.0.0.1') || ($url_tmp['host'] === 'localhost')) {
                        $this->setScannerErrorMessage
                            ($this->messages->getMessageByName('LOCALHOST_SCAN_NOT_ALLOWED'));
                        $this->setScannerHasError(TRUE);
                        return FALSE;
                    }

                    $regex  = "/\b(([1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)(([0-9]|";
                    $regex .= "[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.) {2}([0-9]|";
                    $regex .= "[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b/";
                    $ip;
                    if (preg_match($regex, $url_tmp['host'], $ip) === 1) {
                        /*
                         * Broadcast and mask are hardcoded for now.
                         * With this check the program denies that an attacker
                         * is able to "scan" the local network of the
                         * server. We could get the $bcast and $smask out of
                         * ifconfig or ipconfig. We could also request it by the
                         * admin in a setup script or similar.
                         * --- TODO ---
                         */
                        $bcast = $this->bcast;
                        $smask = $this->smask;
                        if ($this->IP_isLocal($url_tmp['host'], $bcast, $smask) === TRUE) {
                            $this->setScannerErrorMessage
                                ($this->messages->getMessageByName('NOT_REACHABLE'));
                            $this->setScannerHasError(TRUE);
                            return FALSE;
                        }
                    }
                }

                /* Only allow HTTP and HTTPS ports in the URL. */
                if (isset($url_tmp['port'])) {
                    if (($url_tmp['port'] != '80')
                        && ($url_tmp['port'] != '443')) {
                        $this->setScannerErrorMessage
                            ($this->messages->getMessageByName('PORT_DISALLOWED'));
                        $this->setScannerHasError(TRUE);
                        return FALSE;
                    }
                }

                if (isset($url_tmp['user']) || isset($url_tmp['pass'])) {
                    $this->setScannerErrorMessage
                        ($this->messages->getMessageByName('DONT_LEAK_USER_CREDS'));
                    $this->setScannerHasError(TRUE);
                    return FALSE;
                } else {
                    /* URL seems legit. Check headers now. */
                    $this->setHeader($url);
                    $status_code = $this->header[1];

                    if (empty($status_code)) {
                        $this->setScannerErrorMessage
                            ($this->messages->getMessageByName('NOT_REACHABLE'));
                        $this->setScannerHasError(TRUE);
                        return FALSE;
                    } else if ($status_code['http_code'] != '404') {
                        /* Everything seems fine! */
                        $this->url = $url;
                        return $url;
                    } else {
                        $this->setScannerErrorMessage
                            ($this->messages->getMessageByName('NOT_REACHABLE', "404"));
                        $this->setScannerHasError(TRUE);
                        return FALSE;
                    }
                }
            }
        } /* else: no URL given - nothing to do. */
    }

    /**
     * @short: Is the given IP local?
     * @var ip: IP to analyze
     * @var bcast: Broadcast address of server
     * @var smask: Mask address of server
     * @algorithm: Calculates whether $ip is in the local network.
     * * Actually it only calculates if it _could_ be in the local network with
     * * the given broadcast address and mask.
     * @return boolean
     */
    private function IP_isLocal($ip, $bcast, $smask) {
        if (empty($bcast) || empty($smask) || empty($ip))
            return NULL;

        $bcast = ip2long($bcast);
        $smask = ip2long($smask);
        $ip    = ip2long($ip);

        $nmask = $bcast & $smask;

        return (($ip & $smask) == ($nmask & $smask));
    }

    /**
     * Send scan results to defined callbackurls
     */
    public function send_to_callbackurls($result) {
        foreach($this->getCallbackurls() as $url) {
            $this->sendResult_POST(json_encode($result,
                                               JSON_PRETTY_PRINT |
                                               JSON_UNESCAPED_UNICODE |
                                               JSON_UNESCAPED_SLASHES),
                                   $url);
        }
    }

    /**
     * Send $result to $url per POST
     */
    public function sendResult_POST($result, $url) {
        $this->checkURL($url);

        $con = curl_init($url);

        $user_agent  = "Mozilla/5.0 (Windows; U; Windows NT ";
        $user_agent .= "5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1";

        $options = array(
            CURLOPT_HEADER          => false,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_CUSTOMREQUEST   => "POST",
            CURLOPT_POSTFIELDS      => $result,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_FOLLOWLOCATION  => true,
            CURLOPT_AUTOREFERER     => true,
            CURLOPT_SSL_VERIFYPEER  => false,
            CURLOPT_USERAGENT       => $user_agent,
            CURLOPT_CONNECTTIMEOUT  => 10,
            CURLOPT_TIMEOUT         => 10
        );

        /* Use settings defined in $options for the connection */
        curl_setopt_array($con, $options);
        curl_exec($con);
        curl_close($con);

        return 0;
    }
}
?>
