<?php
	/*
		OAuthSimple by jr conlin
		http://unitedHeroes.net/OAuthSimple
		Refactor to PHP by Mr.Jack (https://github.com/ikarius6/OAuthSimple-PHP)
	*/
	class OAuthSimple
    {
		private $_secrets=[];
        private $_default_signature_method= "HMAC-SHA1";
        private $_action = "GET";
        private $_nonce_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

		function __construct($consumer_key, $shared_secret){
			if (!empty($consumer_key)) {
				$this->_secrets['consumer_key'] = $consumer_key; 
            }
			if (!empty($shared_secret)) {
				$this->_secrets['shared_secret'] = $shared_secret; 
            }
		}

        function reset(){
            $this->_parameters=[];
            $this->_path=null;
            return $this;
        }

        /** set the parameters either from a hash or a string
         *
         * @param {string,object} List of parameters for the call, this can either be a URI string (e.g. "foo=bar&gorp=banana" or an object/hash)
         */
        function setParameters($parameters) {
            if (empty($parameters)) {
                $parameters = [];
			}
            if (is_string($parameters)) {
                $parameters=$this->_parseParameterString($parameters); 
			}
            $this->_parameters = $parameters;
            if (empty($this->_parameters['oauth_nonce'])) {
                $this->_getNonce();
			}
            if (empty($this->_parameters['oauth_timestamp'])) {
                $this->_getTimestamp();
			}
            if (empty($this->_parameters['oauth_method'])) {
                $this->setSignatureMethod();
			}
            if (empty($this->_parameters['oauth_consumer_key'])) {
                $this->_getApiKey();
			}
            if(empty($this->_parameters['oauth_token'])) {
                $this->_getAccessToken();
			}
            if(empty($this->_parameters['oauth_version'])) {
                $this->_parameters['oauth_version']=='1.0';
			}

            return $this;
        }

        /** convienence method for setParameters
         *
         * @param parameters {string,object} See .setParameters
         */
        function setQueryString($parameters) {
            return $this->setParameters($parameters);
        }

        /** Set the target URL (does not include the parameters)
         *
         * @param path {string} the fully qualified URI (excluding query arguments) (e.g "http://example.org/foo")
         */
        function setURL($path) {
            if ($path == '') {
                throw new Exception ('No path specified for OAuthSimple.setURL');
			}
            $this->_path = $path;
            return $this;
        }

        /** convienence method for setURL
         *
         * @param path {string} see .setURL
         */
		function setPath($path){
            return $this->setURL($path);
        }

        /** set the "action" for the url, (e.g. GET,POST, DELETE, etc.)
         *
         * @param action {string} HTTP Action word.
         */
        function setAction($action="") {
            if (empty($action)) {
                $action="GET";
			}
            $action = strtoupper($action);
            if (preg_match('[^A-Z]', $action)) {
                throw new Exception ('Invalid action specified for OAuthSimple.setAction');
			}
            $this->_action = $action;
            return $this;
        }

        /** set the signatures (as well as validate the ones you have)
         *
         * @param signatures {object} object/hash of the token/signature pairs {api_key:, shared_secret:, oauth_token: oauth_secret:}
         */
        function setTokensAndSecrets($signatures) {
            if ($signatures)
            {
                foreach($signatures as $signature) {
                    $this->_secrets[i] = $signature;
				}
            }
            // Aliases
            if (!empty($this->_secrets['api_key'])) {
                $this->_secrets['consumer_key'] = $this->_secrets['api_key'];
			}
            if (!empty($this->_secrets['access_token'])) {
                $this->_secrets['oauth_token'] = $this->_secrets['access_token'];
			}
            if (!empty($this->_secrets['access_secret'])) {
                $this->_secrets['oauth_secret'] = $this->_secrets['access_secret'];
			}
            if (!empty($this->_secrets['oauth_token_secret'])) {
                $this->_secrets['oauth_secret'] = $this->_secrets['oauth_token_secret'];
			}
            // Gauntlet
            if (empty($this->_secrets['consumer_key'])) {
                throw new Exception('Missing required consumer_key in OAuthSimple.setTokensAndSecrets');
			}
			if (empty($this->_secrets['shared_secret'])) {
                throw new Exception('Missing required shared_secret in OAuthSimple.setTokensAndSecrets');
			}
            if (!empty($this->_secrets['oauth_token']) && empty($this->_secrets['oauth_secret'])) {
                throw new Exception('Missing oauth_secret for supplied oauth_token in OAuthSimple.setTokensAndSecrets');
			}
            return $this;
        }

        /** set the signature method (currently only Plaintext or SHA-MAC1)
         *
         * @param method {string} Method of signing the transaction (only PLAINTEXT and SHA-MAC1 allowed for now)
         */
        function setSignatureMethod($method="") {
            if (empty($method)) {
                $method = $this->_default_signature_method;
			}
            //TODO: accept things other than PlainText or SHA-MAC1
			$method = strtoupper( $method );
            if (!($method == "PLAINTEXT" || $method == "HMAC-SHA1")) {
                throw new Exception ('Unknown signing method specified for OAuthSimple.setSignatureMethod');
			}
            $this->_parameters['oauth_signature_method']= $method;
            return $this;
        }

        /** sign the request
         *
         * note: all arguments are optional, provided you've set them using the
         * other helper functions.
         *
         * @param args {object} hash of arguments for the call
         *                   {action:, path:, parameters:, method:, signatures:}
         *                   all arguments are optional.
         */
        function sign($args=array()) {
            // Set any given parameters
            if(!empty($args['action'])) {
                $this->setAction($args['action']);
			}
            if (!empty($args['path'])) {
                $this->setPath($args['path']);
                }
            if (!empty($args['method'])) {
                $this->setSignatureMethod($args['method']);
			}
            $this->setTokensAndSecrets(!empty($args['signatures'])?$args['signatures']:"");
            if (!empty($args['parameters'])){
				$this->setParameters($args['parameters']);
            }
            // check the parameters
            $normParams = $this->_normalizedParameters();
            $this->_parameters['oauth_signature']=$this->_generateSignature($normParams);
            return array(
                "parameters"=>$this->_parameters,
                "signature"=> $this->_oauthEscape($this->_parameters['oauth_signature']),
                "signed_url"=> $this->_path . '?' . $this->_normalizedParameters(),
                "header"=> $this->getHeaderString()
            );
        }

        /** Return a formatted "header" string
         *
         * NOTE: This doesn't set the "Authorization: " prefix, which is required.
         * I don't set it because various set header functions prefer different
         * ways to do that.
         *
         * @param args {object} see .sign
         */
        function getHeaderString($args="") {
            if (empty($this->_parameters['oauth_signature'])) {
                $this->sign($args);
			}

            $j = $pName = $pLength = $result = 'OAuth ';
			foreach($this->_parameters as $pName => $parameter)
            {
                if (strstr($pName,"oauth")) {
                    continue;
				}
                if ( is_array($this->_parameters[$pName]) )
                {
                    $pLength = count($this->_parameters[$pName]);
                    for ($j=0;$j<$pLength;$j++)
                    {
						$result .= $pName .'="'.$this->_oauthEscape($this->_parameters[$pName][$j]).'" ';
                    }
                }
                else
                {
                    $result .= $pName . '="'.$this->_oauthEscape($this->_parameters[$pName]).'" ';
                }
            }
            return $result;
        }

        // Start Private Methods.

        /** convert the parameter string into a hash of objects.
         *
         */
        function _parseParameterString($paramString) {
            $elements = preg_split("/&/",$paramString);
			$result=[];

			foreach($elements as $element)
            {
                $keyToken=preg_split("/=/",$element);
                $value='';
                if ($keyToken[1]) {
                    $value=urldecode ($keyToken[1]);
				}
                if($result[$keyToken[0]]){
                    if (!is_array($result[$keyToken[0]]))
                    {
                        $result[$keyToken[0]] = array( $result[$keyToken[0]], $value);
                    }
                    else
                    {
                        array_push( $result[$keyToken[0]], $value);
                    }
                }
                else
                {
                    $result[$keyToken[0]]= $value;
                }
            }
            return $result;
        }

        function _oauthEscape($string="") {
            if (empty($string)) {
                return "";
			}
            if (is_array($string))
            {
                throw new Exception('Array passed to _oauthEscape');
            }
			$patrones = array("/\!/","/\*/","/'/","/\(/","/\)/");
			$sustituciones = array("%21","%2A","%27","%28","%29");
			$string = preg_replace($patrones, $sustituciones, $string);
            return urlencode($string);
        }

        function _getNonce($length=5) {
            $result = "";
			$cLength = strlen($this->_nonce_chars);
            for ($i=0;$i<$length;$i++) {
				$rnum = rand(1, $cLength);
                $result .= substr($this->_nonce_chars, $rnum, 1);
            }
            return $this->_parameters['oauth_nonce']=$result;
        }

        function _getApiKey() {
			if (empty($this->_secrets['consumer_key'])) {
                throw new Exception('No consumer_key set for OAuthSimple.');
			}
            return $this->_parameters['oauth_consumer_key']=$this->_secrets['consumer_key'];
        }

        function _getAccessToken() {
            if (empty($this->_secrets['oauth_secret'])) {
                return '';
			}
            if (empty($this->_secrets['oauth_token'])) {
                throw new Exception('No oauth_token (access_token) set for OAuthSimple.');
			}
            return $this->_parameters['oauth_token'] = $this->_secrets['oauth_token'];
        }

        function _getTimestamp(){
            return $this->_parameters['oauth_timestamp'] = time();
        }                                         

        function _normalizedParameters() {
            $elements = array();
			$paramNames = [];
            $ra = 0;
			foreach($this->_parameters as $paramName=>$parameter)
            {
                if ($ra++ > 1000) {
                    throw new Exception('runaway 1');
				}
				array_unshift( $paramNames, $paramName);
            }
			sort( $paramNames );
			$pLen = count( $paramNames);
            for ($i=0;$i<$pLen; $i++)
            {
                $paramName=$paramNames[$i];
                //skip secrets.
                if (strstr($paramName, "_secret")) {
                    continue;
				}
                if (is_array($this->_parameters[$paramName]))
                {
                    $sorted = $this->_parameters[$paramName];
					sort( $sorted );
                    $spLen = count( $sorted );
                    for ($j=0;$j<$spLen;$j++){
                        if ($ra++ > 1000) {
                            throw new Exception('runaway 1');
						}
						array_push( $elements, $this->_oauthEscape($paramName) . '=' . $this->_oauthEscape($sorted[$j]) );
                    }
                    continue;
                }
				array_push( $elements, $this->_oauthEscape($paramName) . '=' . $this->_oauthEscape($this->_parameters[$paramName]) );
            }
            return join("&", $elements);
        }

        function _generateSignature() {
			$secretKey = $this->_oauthEscape($this->_secrets['shared_secret']).'&'.$this->_oauthEscape(!empty($this->_secrets['oauth_secret'])?$this->_secrets['oauth_secret']:"");
            if ($this->_parameters['oauth_signature_method'] == 'PLAINTEXT')
            {
                return $secretKey;
            }
            if ($this->_parameters['oauth_signature_method'] == 'HMAC-SHA1')
            {
                $sigString = $this->_oauthEscape($this->_action).'&'.$this->_oauthEscape($this->_path).'&'.$this->_oauthEscape($this->_normalizedParameters());
                return $this->b64_hmac_sha1("sha1",$sigString, $secretKey );
            }
            return null;
        }

		function b64_hmac_sha1($function, $data, $key){
			switch($function)
			{
				case 'sha1':
					$pack = 'H40';
					break;
				default:
					if($this->debug)
						$this->OutputDebug($function.' is not a supported an HMAC hash type');
					return('');
			}
			if(strlen($key) > 64)
				$key = pack($pack, $function($key));
			if(strlen($key) < 64)
				$key = str_pad($key, 64, "\0");
			return base64_encode(pack($pack, $function((str_repeat("\x5c", 64) ^ $key).pack($pack, $function((str_repeat("\x36", 64) ^ $key).$data)))));
		}
    }
