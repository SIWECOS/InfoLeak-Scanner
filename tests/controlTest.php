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
    
