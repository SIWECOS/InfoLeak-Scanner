    public function setUp() {
        $this->controller = new Control("siwecos.de", "");
    }
    public function tearDown() {
        unset($this->controller);

        /*
        $createdFiles = Array(
            "/tmp/setHeader.txt",
            "/tmp/callbackPostData.txt",
            "/tmp/testGettingPostParameters.txt",
        );
        
        foreach($createdFiles as $file) {
            unlink($file);
        }
        */
    }

    /**
     * @dataProvider dataProviderSetHeader
     */    
    public function testSetHeader($data_encoded, $expectedResult) {
        $data = json_decode($data_encoded);
        
        $controller = new Control($data->url, $data->userAgent);
        $controller->setDangerLevel($data->dangerLevel);
        $controller->setCallbackurls($data->callbackurls);
        $controller->setUserAgent($data->userAgent);
        
        $model = new Model($controller);
        $view = new View($model, $controller, "POST");

        $this->assertFileExists("/tmp/setHeader.txt");
        $content = file_get_contents("/tmp/setHeader.txt");
        
        $this->assertEquals($content,
                            $expectedResult);
    }

    public function dataProviderSetHeader() {
        $userAgent = "test";
        
        $json = json_encode (
            array(
                "url" => "siwecos.de",
                "dangerLevel" => 0,
                "callbackurls" => array("localhost/InfoLeak-Scanner/tests/testSetHeader.php"),
                "userAgent" => $userAgent
            )  
        );
        
        return [
            [$json, $userAgent]
        ];
    }

    
    /**
     * @dataProvider dataProviderAddHTTP
     */    
    public function testAddHTTP($url, $expectedResult) {
        $reflector = new ReflectionClass('Control');
		$method = $reflector->getMethod("addHTTP");
		$method->setAccessible(true);
 
		$result = $method->invokeArgs($this->controller, array($url));

        $this->assertEquals($result,
                            $expectedResult);
    }

    public function dataProviderAddHTTP() {
        return [
            ["siwecos.de", "http://siwecos.de"],
            ["goögle.de", "http://goögle.de"],
            ["testme.com", "http://testme.com"],
            ["172.12.63.6", "http://172.12.63.6"],
        ];
    }
    
    /**
     * @dataProvider dataProviderCheckURL
     */    
    public function testCheckURL($url, $expectedResult) {
        $reflector = new ReflectionClass('Control');
		$method = $reflector->getMethod("checkURL");
		$method->setAccessible(true);
 
		$result = $method->invokeArgs($this->controller, array($url));

        $this->assertEquals($result,
                            $expectedResult);
    }

    public function dataProviderCheckURL() {
        return [
            ["siwecos.de", "http://siwecos.de"],
            ["127.0.0.1", FALSE],
            ["localhost", FALSE],
            // ["192.168.1.101", FALSE],
            ["/wp_config/test.php", TRUE],
            ["testurl.de:8080", FALSE],
            ["user:pass@example.com", FALSE],
        ];
    }
    
    /**
     * @dataProvider dataProviderCallbacks
     */    
    public function testSendToCallbackurls($data_encoded) {
        $data = json_decode($data_encoded);
        
        $controller = new Control($data->url, $data->userAgent);
        $controller->setDangerLevel($data->dangerLevel);
        $controller->setCallbackurls($data->callbackurls);
        $controller->setUserAgent($data->userAgent);
        
        $model = new Model($controller);
        $view = new View($model, $controller, "POST");

        $this->assertFileExists("/tmp/callbackPostData.txt");
    }

    public function dataProviderCallbacks() {
        $json = json_encode (
            array(
                "url" => "siwecos.de",
                "dangerLevel" => 0,
                "callbackurls" => array("localhost/InfoLeak-Scanner/tests/testCallbackPostData.php"),
                "userAgent" => "test"
            )  
        );
        
        return [
            [$json]
        ];
    }
    
    /**
     * @dataProvider dataProviderUserAgent
     */
    public function testSetUserAgent($userAgent, $expectedUserAgent) {
        $this->controller->setUserAgent($userAgent);
        
        $this->assertEquals($this->controller->getUserAgent(),
                            $expectedUserAgent);
    }

    public function dataProviderUserAgent() {
        return [
            ["", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"],
            ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"],
            ["TEST USER AGENT", "TEST USER AGENT"],
            ["0123456789", "0123456789"],
            ["äöü+#?", "äöü+#?"],
            ["Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36"],
            ["Mozilla/5.0 (Linux; Android 7.1.1; G8231 Build/41.2.A.0.219; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 7.1.1; G8231 Build/41.2.A.0.219; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36"],
            ["Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254", "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254"],
            ["Roku4640X/DVP-7.70 (297.70E04154A)", "Roku4640X/DVP-7.70 (297.70E04154A)"],
            ["Mozilla/5.0 (Linux; Android 5.1; AFTS Build/LMY47O) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/41.99900.2250.0242 Safari/537.36", "Mozilla/5.0 (Linux; Android 5.1; AFTS Build/LMY47O) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/41.99900.2250.0242 Safari/537.36"],
            ["AppleTV6,2/11.1", "AppleTV6,2/11.1"],
            ["Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US", "Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US"],
            ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"],
            ["Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3.0+", "Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3.0+"],
            ["Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)", "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)"]
        ];
    }

    /**
     * @dataProvider dataProviderPOST
     * @depends testSetUserAgent
     */    
    public function testSendResult_POST($result, $url, $md5FileContent) {
        $result = $this->controller->sendResult_POST($result, $url);
        
        $this->assertEquals(0, $result);
        $this->assertFileExists("/tmp/testGettingPostParameters.txt");

        $fileContent = file_get_contents("/tmp/testGettingPostParameters.txt");
        $md5 = hash_file('md5', "/tmp/testGettingPostParameters.txt");
        
        $this->assertEquals($md5, $md5FileContent);
    }

    public function dataProviderPOST() {
        return [
            ["{\"url\":\"siwecos.de\",\"dangerLevel\":0,\"callbackurls\":[\"test\"]}", "http://localhost/InfoLeak-Scanner/tests/testPOST.php", "22f2bd739903334c35623e1717619204"]
        ];
    }
    
    /**
     * @dataProvider dataProviderPunycode
     */
    public function testPunycodeUrl($url, $punycode) {
        //$this->markTestSkipped('must be revisited.');
        
        $this->assertEquals($punycode, $this->controller->punycodeUrl($url));
    }

    public function dataProviderPunycode() {
        return [
            ["https://www.wattläufer-peters.de/", "https://www.xn--wattlufer-peters-znb.de/"],
            ["https://bluecȯat.com", "https://xn--bluecat-x2c.com"],
            ["https://bluecoạt.com", "https://xn--bluecot-fn4c.com"],
            ["https://bluecoaṫ.com", "https://xn--bluecoa-393c.com"],
            ["https://㯙㯜㯙㯟.com", "https://xn--domain.com"],
            ["https://hääää.de", "https://xn--h-0faaaa.de"],
            ["https://üüüü.com", "https://xn--tdaaaa.com"],
            ["https://mö-süte-üst-cüül.de", "https://xn--m-ste-st-cl-rfb4fdea.de"],
            ["", ""],
            ["108.177.127.94", "108.177.127.94"]
        ];
    }

    /**
     * @dataProvider dataProviderIP
     */
    public function testIP_isLocal($ip, $bcast, $smask) {
        //$this->markTestSkipped('must be revisited.');

        $reflector = new ReflectionClass('Control');
		$method = $reflector->getMethod("IP_isLocal");
		$method->setAccessible(true);
 
		$result = $method->invokeArgs($this->controller, array($ip, $bcast, $smask));
 
		$this->assertTrue($result);
    }

