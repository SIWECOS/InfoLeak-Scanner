<?php

namespace Tests\Unit;

use Tests\TestCase;
use Illuminate\Foundation\Testing\WithFaker;
use Illuminate\Foundation\Testing\RefreshDatabase;

class HTTPTest extends TestCase
{
    private $test_url = "google.de";
    private $punycode_url = "http://äü.de";

    /**
       === General Tests ===
    **/
    
    /**
     * This tests whether the URL gets punycode encoded
     *
     * @return void
     */
    public function testPunycode_GET()
    {
        $response = $this->get('/?url=' . $this->punycode_url);


        $response->assertStatus(200);
        $this->assertInternalType('array', json_decode($response->getContent(), true));
    }  

    /**
       === POST Tests ===
    **/

    /**
     * This tests whether response is valid JSON.
     *
     * @return void
     */
    public function test_POST()
    {
        $response = $this->withHeaders([
            'Content-Type' => 'application/json',
        ])->json('POST', '/start', [
            "url" => 'eco.de',
            "dangerLevel" => 0,
            "callbackurls" => ["http://localhost:8001/test2.php"],
            "userAgent" => "TESTING_USER_AGENT"
        ]);

        $response->assertStatus(200);
    }

    /**
     * This tests whether the request is getting dispatched.
     *
     * @return void
     */
    public function testDispatch_POST()
    {
        $response = $this->withHeaders([
            'Content-Type' => 'application/json',
        ])->json('POST', '/start', [
            "url" => 'eco.de',
            "dangerLevel" => 0,
            "callbackurls" => ["http://localhost:8001/test2.php"],
            "userAgent" => "TESTING_USER_AGENT"
        ]);

        $this->assertEquals('OK', $response->getContent());
    }




    /**
       === GET Tests ===
    **/

    /**
     * This test should redirect, as the request is invalid (no URL).
     *
     * @return void
     */
    public function testShouldRedirect_GET()
    {
        $response = $this->get('/');

        $response->assertStatus(302);
    }

    /**
     * This test should analyze google (GET).
     *
     * @return void
     */
    public function testConnecting_GET()
    {
        $response = $this->get('/?url=' . $this->test_url);

        $response->assertStatus(200);
    }

    /**
     * This tests whether response is valid JSON.
     *
     * @return void
     */
    public function testJSON_GET()
    {
        $response = $this->get('/?url=' . $this->test_url)->getContent();

        $data = json_decode($response, true);

        $this->assertInternalType('array', $data);
    }
}
