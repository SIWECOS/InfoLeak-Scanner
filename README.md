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


## Why?
TODO

## Risk
```
| Finding                         | Score (0-10) |
|---------------------------------+--------------|
| Content-Management-System (CMS) |            6 |
| Plugins                         |            7 |
| JavaScript libraries            |            5 |
| Mails adresses                  |            7 |
| Phone numbers                   |            4 |
```

Risks are set using:

[Vulnerability Scoring System Version 3.0 Calculator](https://www.first.org/cvss/)

[JavaScript](https://www.sourceclear.com/registry/security/information-disclosure/javascript/sid-2371/risk)

[E-Mail](http://www.huawei.com/en-CA/psirt/security-advisories/2016/huawei-sa-20161214-01-smartphone-en)

## Output

### Nonverbose mode
No findings in any checks:
```
{
    "checks": {
        "cms": {
            "result": false,
            "risk": 0
        },
        "plugin": {
            "result": false,
            "risk": 0
        },
        "javascript": {
            "result": false,
            "risk": 0
        },
        "email": {
            "result": false,
            "risk": 0
        },
        "phone": {
            "result": false,
            "risk": 0
        }
    }
}
```


At least one finding in any check:
```
{
    "checks": {
        "cms": {
            "result": true,
            "risk": 6
        },
        "plugin": {
            "result": true,
            "risk": 7
        },
        "javascript": {
            "result": true,
            "risk": 5
        },
        "email": {
            "result": true,
            "risk": 7
        },
        "phone": {
            "result": true,
            "risk": 4
        }
    }
}
```

### Verbose mode
No findings in any checks:
```
{
    "checks": {
        "cms": {
            "result": false,
            "risk": 0,
            "comment": "Es konnte keine CMS detektiert werden.",
            "finding": "N/A."
        },
        "plugin": {
            "result": false,
            "risk": 0,
            "comment": "Es konnten keine Plugins gefunden werden.",
            "finding": "N/A."
        },
        "javascript": {
            "result": false,
            "risk": 0,
            "comment": "Es konnte keine JavaScript Bibliothek gefunden werden.",
            "finding": "N/A."
        },
        "email": {
            "result": false,
            "risk": 0,
            "comment": "Es konnte keine E-Mail Adresse gefunden werden.",
            "finding": "N/A."
        },
        "phone": {
            "result": false,
            "risk": 0,
            "comment": "Es konnten keine Telefonnummern gefunden werden.",
            "finding": "N/A."
        }
    }
}
```

At least one finding in any check:
```
{
    "checks": {
        "cms": {
            "result": true,
            "risk": 6,
            "comment": "Die verwendete CMS konnte ermittelt werden (wordpress).",
            "finding": "[img]: [...]"
        },
        "plugin": {
            "result": true,
            "risk": 7,
            "comment": [
                "Ein verwendetes Plugin konnte detektiert werden (contact-form-7).",
                "Ein verwendetes Plugin konnte detektiert werden (styles).",
                "Ein verwendetes Plugin konnte detektiert werden (groups)."
            ],
            "finding": [
                "[...]/contact-form-7/includes/css/styles.css?ver=4.8",
                "[...]/contact-form-7/includes/css/styles.css?ver=4.8",
                "[...]?gid=416&trk=group-name"
            ]
        },
        "javascript": {
            "result": true,
            "risk": 5,
            "comment": "Es wurde eine JavaScript Bibliothek gefunden für dessen Version eine Schwachstelle existiert (jquery 1.4.1).",
            "finding": {
                "attr": "[...]/wp-includes/js/jquery/jquery-migrate-1.4.1.js",
                "version": "1.4.1"
            }
        },
        "email": {
            "result": true,
            "risk": 7,
            "comment": "Die Offenlegung von E-Mail Adressen könnte zu ungewünschtem Spam und unter anderem auch zu einer gezielten Phishing Attacke führen.",
            "finding": "mail1@host.de, mail2@host.de, mail3@host.de"
        },
        "phone": {
            "result": true,
            "risk": 4,
            "comment": "Die Offenlegung von Telefonnummern....",
            "finding": "123456, 654321"
        }
    }
}
```


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



