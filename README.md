# InfoLeak-Scanner

## Docker
First run `docker run --rm -p 8000:80 siwecos/infoleak-scanner`.

Open your browser and use the scanner: `http://localhost/?url=<URL>`

## Install

Get php5, curl and a webserver:
```
sudo apt-get install apache2 php5 php5-curl
```

Copy application into webserver:
```
cp -R . /var/www/html/
```

## What?

### Content-Management-System (CMS)
- Drupal
- Joomla
- vbulletin
- Veyton
- Webspell
- Wordpress
- xt-commerce

### Plugins
Searches plugins for the detected CMS. Biggest list (wordpress) contains 980 different plugins.

### JavaScript libraries
Searches for vulnerable and most used JavaScript libraries.

### Mail adresses
Searches for mail adresses. Interesting for spam and/or social engineering attacks.

### Phone numbers
Searches for phone numbers. Interesting for social engineering attacks and/or scam.


## Score
```
| Finding                         | Score (0-100) |
|---------------------------------+---------------|
| Content-Management-System (CMS) |            60 |
| Plugins                         |            70 |
| JavaScript libraries            |            50 |
| Mails adresses                  |            70 |
| Phone numbers                   |            40 |
```

Scores are set using:

[Vulnerability Scoring System Version 3.0 Calculator](https://www.first.org/cvss/)

[JavaScript](https://www.sourceclear.com/registry/security/information-disclosure/javascript/sid-2371/risk)

[E-Mail](http://www.huawei.com/en-CA/psirt/security-advisories/2016/huawei-sa-20161214-01-smartphone-en)


## Running the scanner
You can run the scanner via POST and GET requests.

### POST
If you want to run the scanner with a POST request you have to send the
parameters in a JSON encoded format:
``` 
{
  "url": "string",
  "dangerLevel": 0,
  "callbackurls": [
    "string"
  ]
}
```
`url` defines the URL which should be scanned.
`dangerLevel` is not relevant, simply define it to 0.
`callbackurls` is an array of URLs. These URLs will get the result of the
scanner (sent via POST).

### GET
Running the scanner with a GET request is much simpler. All you have to do is to
run the application with a given URL:

`http://localhost/?url=<URL>`


## Output

No findings in any scans:
```
{
    "name": "InfoLeak-Scanner",
    "hasError": false,
    "errorMessage": null,
    "score": 0,
    "tests": [
        {
            "name": "CMS",
            "hasError": false,
            "errorMessage": null,
            "score": 0,
            "scoreType": "info",
            "testDetails": [
                null
            ]
        },
        {
            "name": "CMS_PLUGINS",
            "hasError": false,
            "errorMessage": null,
            "score": 0,
            "scoreType": "warning",
            "testDetails": [
                null
            ]
        },
        {
            "name": "JS_LIB",
            "hasError": false,
            "errorMessage": null,
            "score": 0,
            "scoreType": "warning",
            "testDetails": [
                null
            ]
        },
        {
            "name": "EMAIL_ADDRESS",
            "hasError": false,
            "errorMessage": null,
            "score": 0,
            "scoreType": "info",
            "testDetails": [
                null
            ]
        },
        {
            "name": "PHONE_NUMBER",
            "hasError": false,
            "errorMessage": null,
            "score": 0,
            "scoreType": "info",
            "testDetails": [
                null
            ]
        }
    ]
}
```

At least one finding in every scan:
```
{
    "name": "InfoLeak-Scanner",
    "hasError": false,
    "errorMessage": null,
    "score": 58,
    "tests": [
        {
            "name": "CMS",
            "hasError": false,
            "errorMessage": null,
            "score": 60,
            "scoreType": "info",
            "testDetails": [
                {
                    "placeholder": "CMS_VERSION",
                    "values": {
                        "cms": "wordpress",
                        "version": "4.9.1",
                        "node": "meta",
                        "node_content": "content : WordPress 4.9.1"
                    }
                }
            ]
        },
        },
        {
            "name": "CMS_PLUGINS",
            "hasError": false,
            "errorMessage": null,
            "score": 70,
            "scoreType": "warning",
            "testDetails": [
                {
                    "placeholder": "PLUGIN_ONLY",
                    "values": {
                        "plugin": "styles",
                        "node": "href",
                        "node_content": "[...]/wp-content/plugins/contact-form-7/"
                    }
                }
            ]
        },
        {
            "name": "JS_LIB",
            "hasError": false,
            "errorMessage": null,
            "score": 50,
            "scoreType": "warning",
            "testDetails": [
                {
                    "placeholder": "JS_LIB_VULN_VERSION",
                    "values": {
                        "js_lib_name": "jquery",
                        "js_lib_version": "1.4.1",
                        "node": "src",
                        "node_content": "[...]/wp-includes/js/jquery/jquery-migrate-1.4.1.js"
                    }
                }
            ]
        },
        {
            "name": "EMAIL_ADDRESS",
            "hasError": false,
            "errorMessage": null,
            "score": 70,
            "scoreType": "info",
            "testDetails": [
                {
                    "placeholder": "EMAIL_FOUND",
                    "values": {
                        "email_address": [
                            [
                                "user@domain.de",
                                "admin@domain.de"
                            ]
                        ]
                    }
                }
            ]
        },
        {
            "name": "PHONE_NUMBER",
            "hasError": false,
            "errorMessage": null,
            "score": 40,
            "scoreType": "info",
            "testDetails": [
                {
                    "placeholder": "NUMBER_FOUND",
                    "values": {
                        "number": [
                            "0123-10 00 22-2",
                            "0123-20 00 33-444"
                        ]
                    }
                }
            ]
        }
    ]
}
```

# Scanner Interface Values

## InfoLeak-Scanner

### Messages

| Placeholder                | Message                                                                                                                                   |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------- |
| **SCAN CMS**               | 								                                                                                                          |
| CMS_ONLY                   | Used Content-Management-System {cms} detected.                                                                                            |
| CMS_VERSION                | Used Content-Management-System {cms} and its version {version} detected.                                                                  |
| CMS_VERSION_VULN           | Vulnerable Content-Management-System {cms} version {version} detected                                                                     |
| **SCAN PLUGIN**            |                                                                                                                                           |
| PLUGIN_ONLY                | CMS Plugin {plugin} in DOM-node {node} via node-content {node_content} detected.                                                          |
| PLUGIN_VERSION             | CMS Plugin {plugin} and its version {plugin_version} in DOM-node {node} via node-content {node_content} detected.                         |
| PLUGIN_VERSION_VULN        | Vulnerable CMS Plugin {plugin} and its version {plugin_version} in DOM-node {node} via node-content {node_content} detected.              |
| **SCAN JS**                |                                                                                                                                           |
| JS_LIB_ONLY                | Used JavaScript library {js_lib_name} in DOM-node {node} via node-content {node_content} detected.                                        |
| JS_LIB_VERSION             | Used JavaScript library {js_lib_name} and its version {js_lib_version} in DOM-node {node} via node-content {node_content} detected.       |
| JS_LIB_VULN_VERSION        | Vulnerable JavaScript library {js_lib_name} and its version {js_lib_version} in DOM-node {node} via node-content {node_content} detected. |
| **SCAN EMAIL**             |                                                                                                                                           |
| EMAIL_FOUND                | Email address {email_address} found.                                                                                                      |
| **SCAN PHONE**             |                                                                                                                                           |
| NUMBER_FOUND               | Telephone number {number} found.                                                                                                          |
|                            |                                                                                                                                           |
| **ERRORS**                 |                                                                                                                                           |
| NO_SOURCE_CODE             | Given URL has no source code.                                                                                                             |
| NO_VALID_URL               | Given URL is not a valid URL.                                                                                                             |
| LOCALHOST_SCAN_NOT_ALLOWED | Scanning localhost ist not permitted.                                                                                                     |
| NOT_REACHABLE              | Given URL is not reachable.                                                                                                               |
| PORT_DISALLOWED            | Given URL contains a disallowed port.                                                                                                     |
| DONT_LEAK_USER_CREDS       | Given URL contains user credentials.                                                                                                      |
| JSON_DECODE_ERROR          | Given POST request could not be decoded.                                                                                                  |
| REDIRECT_ERROR             | URL does a forbidden redirect                                                                                                                                          |



## Further details
Especially tested on:

```
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
```



