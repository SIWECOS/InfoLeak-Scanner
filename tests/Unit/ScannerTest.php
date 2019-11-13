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
use App\Libs\Analyser;

class ScannerTest extends TestCase
{
  public function tearDown(): void
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
    $e = new \GuzzleHttp\Exception\RequestException(
      "Error Communicating with Server",
      new Request('GET', 'test')
    );

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

    foreach ($view["tests"] as $test) {
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

    foreach ($view["tests"] as $test) {
      $this->assertInternalType('string', $test["name"]);
      $this->assertEquals($test["errorMessage"], null);
      $this->assertEquals($test["hasError"], null);
      $this->assertInternalType('integer', $test["score"]);
      $this->assertInternalType('string', $test["scoreType"]);
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
  }

  /**
   * Check whether Analyser works correctly
   *
   * @return void
   */
  public function testAnalyser()
  {
    $analyser = new Analyser("http://SCANNER-PHP-UNIT-TEST.com", "");

    /**
          ======== TESTING find_email ========
     **/

    $mail_adresses = [
      "easy@mail.com", "x@y.com", "test0@email.de",
      "easy1[at]mail.com", "easy=?^2[at]mail.com",
      "my.mail[at]hoster.to", "number11[at]gmx.de",
      "me#easy@mail.com", "me#easy|}~@mail.com", "me.*+-/=?^_`{|}~easy@mail.com"
      //"&#116;&#101;&#115;&#116;&#064;&#109;&#097;&#105;&#108;&#046;&#100;&#101", // test@mail.de encoded
    ];
    $email_source = <<<EOT
<html>
<body>
easy $mail_adresses[0]
inquotes "$mail_adresses[1]"
mailto mailto:$mail_adresses[2]
a href="mailto:$mail_adresses[3]"
askdbasd "$mail_adresses[4]" kjasdasd
$mail_adresses[5]
$mail_adresses[6]
$mail_adresses[7]
$mail_adresses[8]
$mail_adresses[9]
</body>
</html>
EOT;
    $email_analysis = $analyser->find_email($email_source);

    // NOTE(ya): Check whether results match original adresses precisely
    foreach ($email_analysis as $email) {
      $this->assertContains($email, $mail_adresses);
    }

    // NOTE(ya): Are all tested emails getting detected?
    $this->assertEquals(10, count($email_analysis));
  }


  /** @test */
  public function the_email_analyser_will_not_fetch_an_invalid_email_containing_a_slash()
  {
    $analyser = new Analyser("http://SCANNER-PHP-UNIT-TEST.com", "");
    $emails = $analyser->find_email("/publickey.mail@example.org");

    $this->assertCount(1, $emails);
    $this->assertEquals('publickey.mail@example.org', $emails[0]);
  }
}
