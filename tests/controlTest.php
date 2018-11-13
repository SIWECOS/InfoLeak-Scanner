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
