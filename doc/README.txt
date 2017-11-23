

================================================================================
				   INSTALL				
================================================================================
Short: apt-get install apache2 php5 php5-curl
       cp siwecos /var/www/html/
       Surf: http://localhost/index.php?url=rub.de


For testing you could also run a temporary webserver with PHP. For this you have
to extract the program "cd" into that directory and run
	$ php -S localhost:8000

The application will be available on localhost port 8000 now. Open the browser
and surf to:
	http://localhost:8000/index.php?url=rub.de

Now you should already see the result of the analysis. As you probably noticed
you are specifying the target with the GET-Parameter "url". You can replace
"rub.de" with any URL you want and watch the analysis happen.


You need PHP and a webserver:
	$ apt-get install apache2 php5

There is no DBMS needed, everything is handled with files.
The connection is build with cURL, so it has to be installed. This is done in
Debian with:
	$ apt-get install php5-curl


================================================================================
				   OUTPUT				
================================================================================

All negative example: 
{
    "checks": {
        "cms": {
            "result": false,
            "comment": "Es konnte keine CMS detektiert werden.",
            "finding": "N/A"
        },
        "plugin": {
            "result": false,
            "comment": "Es konnten keine Plugins gefunden werden.",
            "finding": "N/A"
        },
        "javascript": {
            "result": false,
            "comment": "Es konnte keine Javascript Bibliothek gefunden werden.",
            "finding": "N/A"
        },
        "email": {
            "result": false,
            "comment": "Es konnte keine E-Mail Adresse gefunden werden.",
            "finding": "N/A"
        }
    }
}


All positive example:
{
    "checks": {
        "cms": {
            "result": true,
            "comment": "Die verwendete CMS konnte ermittelt werden (wordpress).",
            "finding": "[meta]: content : Wir gestalten minimalistische,
	    responsive WordPress Themes und teilen auf unserem Blog fin [...]" 
        },
        "plugin": {
            "result": true,
            "comment": [
                "Ein verwendetes Plugin konnte detektiert werden (jetpack).",
                "Ein verwendetes Plugin konnte detektiert werden (contact-form-7).",
                "Ein verwendetes Plugin konnte detektiert werden (woocommerce)."
            ],
            "finding": [
                "http://URL/wp-content/plugins/jetpack/css/jetpack.css?ver=4.7",
                "http://URL/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=4.7",
                "http://URL/wp-content/plugins/woocommerce-multilingual/res/css/admin.css?ver=4.0.4"
            ]
        },
        "javascript": {
            "result": true,
            "comment": "Es wurde eine Javascript Bibliothek gefunden für dessen
	    Version eine Schwachstelle existiert (jquery 1.4.1).", 
            "finding": {
                "attr": "http://URL/wp-includes/js/jquery/jquery-migrate.min.js?ver=1.4.1",
                "version": "1.4.1"
            }
        },
        "email": {
            "result": true,
            "comment": "Die Offenlegung von E-Mail Adressen könnte zu
	    ungewünschtem Spam und unter anderem auch zu einer gezielten
	    Phishing Attacke führen.", 
            "finding": "webmaster@URL.de"
        }
    }
}

As you can see there are 4 topics being analysed: cms, plugin, javascript and
email. The output of those topics are bound to the fields of: 

| Field   | Type            | Description                                |
|---------+-----------------+--------------------------------------------|
| result  | Boolean         | True if there was a finding, else false.   |
| comment | String (German) | Short description of the finding.          |
| finding | String          | Excerpt of the origin node for the finding |
|         |                 | (bound to 100 chars output). Prints "N/A"  |
|         |                 | if there were no results.                  |


All 4 topics will be listed in the output, even if there were no findings. There
will always be only one result field for one topic. 

| Topic      | Max result count | Detects version |
|------------+------------------+-----------------|
| CMS        |                1 | Yes             |
| Plugins    |                3 | Yes             |
| JavaScript |                1 | Yes             |
| E-Mail     |                1 | No              |

Found versions will be printed in comments. In case of JavaScript libraries
there will be up to two sections in the finding field "attr" and "version" which
can occur for up to three found JavaScript libraries. The "attr" will print the
affected attribute node found in the DOM and "version" (only if detected) will
print the detected version of that library. In case of a known vulnerability for
that specific version of the library, there will be an appropriate statement in
the comment like "Es wurde eine Javascript Bibliothek gefunden für dessen
Version eine Schwachstelle existiert (jquery 1.4.1)." (see above). 


================================================================================
				   Errors				
================================================================================

"Sorry, the given address has no source code."
- Fetched source code happened to be empty
- Curl timeout is set to 10 seconds

"Sorry, this does not look like a valid URL."
- Given URL didn't pass the URL validation process

"Sorry, I am not able to communicate on that port."
- Prevent attacks - only port 80 allowed

"Scanning localhost is not allowed."
- Prevent attacks on server

"Sorry, the given address is not reachable."
- Tried to access local IP

"Sorry, the given address is not reachable. (404)"

"You should not tell me your username/password for other services."
- Prevent users revealing their username/password 


================================================================================
				   Notes				
================================================================================

This application is tested on:
	Mozilla Firefox 45.7.0

	PHP 5.6.30-0+deb8u1 (cli) (built: Feb  8 2017 08:50:21) 
	Copyright (c) 1997-2016 The PHP Group
	Zend Engine v2.6.0, Copyright (c) 1998-2016 Zend Technologies

	Server version: Apache/2.4.10 (Debian)
	Server built:   Feb 24 2017 18:40:28
	Server's Module Magic Number: 20120211:37
	Server loaded:  APR 1.5.1, APR-UTIL 1.5.4
	Compiled using: APR 1.5.1, APR-UTIL 1.5.4
	Architecture:   64-bit
	Server MPM:     prefork
	threaded:     no
	forked:     yes (variable process count)
	Server compiled with....
	-D APR_HAS_SENDFILE
	-D APR_HAS_MMAP
	-D APR_HAVE_IPV6 (IPv4-mapped addresses enabled)
	-D APR_USE_SYSVSEM_SERIALIZE
	-D APR_USE_PTHREAD_SERIALIZE
	-D SINGLE_LISTEN_UNSERIALIZED_ACCEPT
	-D APR_HAS_OTHER_CHILD
	-D AP_HAVE_RELIABLE_PIPED_LOGS
	-D DYNAMIC_MODULE_LIMIT=256
	-D HTTPD_ROOT="/etc/apache2"
	-D SUEXEC_BIN="/usr/lib/apache2/suexec"
	-D DEFAULT_PIDLOG="/var/run/apache2.pid"
	-D DEFAULT_SCOREBOARD="logs/apache_runtime_status"
	-D DEFAULT_ERRORLOG="logs/error_log"
	-D AP_TYPES_CONFIG_FILE="mime.types"
	-D SERVER_CONFIG_FILE="apache2.conf"
