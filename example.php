<?php
	/*
		OAuthSimple by jr conlin
		http://unitedHeroes.net/OAuthSimple
		Refactor to PHP by Mr.Jack (https://github.com/ikarius6/OAuthSimple-PHP)
	*/
	include 'OAuthSimple.php';
	$oauth = new OAuthSimple("MYAPIKEY","MYSECRET");
	$otherParams = array(
		"oauth_token"=>"",
		"oauth_version"=>"1.0",
		"uid"=>"someextraparam",
		//"oauth_nonce" => "mrjack",
		//"oauth_timestamp" => "1458685996"
	);
	$oauth->setParameters($otherParams);

	$signedResult = $oauth->sign( array("action"=>'GET', "path"=> "http://SOMEURL/", "method"=>'HMAC-SHA1', "parameters"=>$otherParams) );
	echo "<pre>";
	print_r( $signedResult );