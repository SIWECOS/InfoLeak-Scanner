<?php

namespace Tests\Unit;

use Tests\TestCase;
use Illuminate\Foundation\Testing\WithFaker;
use Illuminate\Foundation\Testing\RefreshDatabase;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\RequestException;
use Mockery;

use App\Libs\View;

class ScannerTest extends TestCase
{
    public function tearDown() :void
    {
        parent::tearDown();
        \Mockery::close();
    }
    
    /**
     * Check whether error messages are valid and not malformed
     *
     * @return void
     */
    public function testPrintError()
    {
        $e = new \GuzzleHttp\Exception\RequestException("Error Communicating with Server",
                                                        new Request('GET', 'test'));
        
        $view = new View(file_get_contents(base_path('VERSION')));
        $view = $view->printError($e->getMessage(), get_class($e));
        
        $this->assertInternalType('array', $view);
    }

    /**
     * Check whether response is as specified
     *
     * @return void
     */
    public function testPrintResult()
    {
        $view = new View(file_get_contents(base_path('VERSION')));

        $view = $view->printJSON("Wordpress", ["test@email.com"], null, null, ["1234567"]);

        
        /**
           === Check keys ===
        **/
        $this->assertArrayHasKey('name', $view);
        $this->assertArrayHasKey('version', $view);
        $this->assertArrayHasKey('hasError', $view);
        $this->assertArrayHasKey('score', $view);
        $this->assertArrayHasKey('tests', $view);

        foreach($view["tests"] as $test) {
            $this->assertArrayHasKey('name', $test);
            $this->assertArrayHasKey('hasError', $test);
            $this->assertArrayHasKey('score', $test);
            $this->assertArrayHasKey('scoreType', $test);
            $this->assertArrayHasKey('testDetails', $test);
        }

        /**
           === Check types ===
        **/
        $this->assertInternalType('array', $view);
        $this->assertInternalType('string', $view["version"]);
        $this->assertEquals($view["hasError"], null);
        $this->assertEquals($view["errorMessage"], null);
        $this->assertInternalType('float', $view["score"]);
        $this->assertInternalType('array', $view["tests"]);

        foreach($view["tests"] as $test) {
            $this->assertInternalType('string', $test["name"]);
            $this->assertEquals($test["errorMessage"], null);
            $this->assertEquals($test["hasError"], null);
            $this->assertInternalType('integer', $test["score"]);
            $this->assertInternalType('string', $test["scoreType"]);
            //$this->assertInternalType('array', $test["scoreType"]);
        }

        /**
           === Check values ===
        **/
        $this->assertEquals($view["name"], "INFOLEAK");
        $this->assertEquals($view["score"], "99");

        // tests 0
        $this->assertEquals($view["tests"][0]["score"], "100");
        $this->assertEquals($view["tests"][0]["name"], "CMS_PLUGINS");
        $this->assertEquals($view["tests"][0]["scoreType"], "warning");

        // tests 1
        $this->assertEquals($view["tests"][1]["score"], "100");
        $this->assertEquals($view["tests"][1]["name"], "JS_LIB");
        $this->assertEquals($view["tests"][1]["scoreType"], "warning");
        
        // tests 2
        $this->assertEquals($view["tests"][2]["score"], "96");
        $this->assertEquals($view["tests"][2]["name"], "EMAIL_ADDRESS");
        $this->assertEquals($view["tests"][2]["scoreType"], "info");
        $this->assertEquals($view["tests"][2]["testDetails"][0]["translationStringId"], "EMAIL_FOUND");
        $this->assertEquals($view["tests"][2]["testDetails"][0]["placeholders"]["email_adress"], "test@email.com");
        
        // tests 3
        $this->assertEquals($view["tests"][3]["score"], "98");
        $this->assertEquals($view["tests"][3]["name"], "PHONE_NUMBER");
        $this->assertEquals($view["tests"][3]["scoreType"], "info");
        $this->assertEquals($view["tests"][3]["testDetails"][0]["translationStringId"], "NUMBER_FOUND");
        $this->assertEquals($view["tests"][3]["testDetails"][0]["placeholders"]["number"], "1234567");

        /**
           === Check scoring ===
        **/
        unset($view);
        $view = new View(file_get_contents(base_path('VERSION')));
        $view = $view->printJSON("Wordpress", null, null, null, ["1234567"]);
        $this->assertEquals($view["score"], "100");

        $view = new View(file_get_contents(base_path('VERSION')));
        $view = $view->printJSON("Wordpress", null, null, null, null);
        $this->assertEquals($view["score"], "100");

        $view = new View(file_get_contents(base_path('VERSION')));
        $view = $view->printJSON(null, null, null, null, null);
        $this->assertEquals($view["score"], "100");

        $view = new View(file_get_contents(base_path('VERSION')));
        $p = array();
        $p["result"] = [true];
        $p["pVal"] = ["/path/to/YoastSEO"];
        $p["attrName"] = ["href"];
        $p["version"] = ["1.7.3.3"];
        $p["plugin_name"] = ["YoastSEO"];
        $view = $view->printJSON("Wordpress", ["test@email.com"], $p, null, ["1234567"]);
        $this->assertEquals($view["score"], "20");

        $view = new View(file_get_contents(base_path('VERSION')));
        $p = array();
        $p["result"] = [false];
        $p["pVal"] = ["/path/to/YoastSEO"];
        $p["attrName"] = ["href"];
        $p["version"] = ["1.7.3.3"];
        $p["plugin_name"] = ["YoastSEO"];
        $view = $view->printJSON("Wordpress", ["test@email.com"], $p, null, ["1234567"]);
        $this->assertEquals($view["score"], "98");

        /* TODO(ya): js lib vuln
        $view = new View(file_get_contents(base_path('VERSION')));
        $p = array();
        $p["result"] = [true];
        $p["pVal"] = ["/path/to/YoastSEO"];
        $p["attrName"] = ["href"];
        $p["version"] = ["1.7.3.3"];
        $p["plugin_name"] = ["YoastSEO"];
        $j = array();
        $j["isVuln"] = [true];
        $j["version"] = ["2.0.3"];
        $j["lib"] = ["jquery"];
        $j["node"] = ["script"];        
        $view = $view->printJSON("Wordpress", ["test@email.com"], $p, $j, ["1234567"]);
        print_r($view);
        $this->assertEquals($view["score"], "98");
        */
    }
}
