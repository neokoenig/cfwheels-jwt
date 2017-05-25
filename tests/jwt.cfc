component extends="wheels.Test"  hint="Unit Tests" {


	function setup(){
		secretkey="abcdefg";
		jwtObj = jwt(secretkey);
		/* Test tokens can be generated at https://jwt.io/ and Epoch time from http://www.epochconverter.com/*/
		testData = {
			payload = {
			  "sub": "1234567890",
			  "name": "John Doe",
			  "admin": true
			},
			// Uses payload
			validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.e0CFuBLfhSbH7bQIVrIODvMIcdiKBpmk0TVcWE288dQ",
			invalidFormatToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0cyI6IkZlYnJ1YXJ5LCAwNSAyMDE0IDEyOjA4OjA1IiwidXNlcmlkIjoiamRvZSJ9",
			// Payload signed with invalid signature
			invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.ruc_ziwPAc2QnO2zrrrEL_Fn-SSjtczeW4SeQGcjUn0",
			/*
			exp: 2037-12-31 17:00:00 GMT Last year that we can convert using dateAdd in ACF
			{
			  "iss": "http://myapi",
			  "aud": "clientid",
			  "exp" : 2145891600
			  "sub": "1234567890",
			  "name": "John Doe",
			  "admin": true
			} */
			tokenWithClaims = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbXlhcGkiLCJhdWQiOiJjbGllbnRpZCIsImV4cCI6MjE0NTg5MTYwMCwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.EGZZwFvl9q_44Pq5wH18FZ_R4r7FsXegkf_onRvQqU8",
			//exp: 1999-01-01 00:00:00
			expiredTokenWithClaims = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbXlhcGkiLCJhdWQiOiJjbGllbnRpZCIsImV4cCI6OTE1MTQ4ODAwLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.HZXXIsXFO6yp8SDlL91PpuPVo_fbMXxKzOj4lCNkaV8",
			//nbf: 1999-01-01 00:00:00 GMT
			validNotBefore = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjkxNTE0ODgwMCwic3ViIjoieHl6In0.-KjrG0ktPVz-RrEhf79NCiWASljbA--wYjK2ykC_bbw",
			//nbf: 2999-01-01 00:00:00 GMT
			invalidNotBefore = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjMyNDcyMTQ0MDAwLCJzdWIiOiJ4eXoifQ.I13RhKA9iflSJ2xLHxgUARYe7IRuf7J_MlGFkNKj3cQ"
		};
	}
	function teardown(){
		jwtObj = "";
	}

	function Test_encode_and_decode_default(){
		// Encode the data structure as a json web token
		// NB, using "token" as a variable name seems to cause issues
		thetoken = jwtObj.encode(testData.payload);
		assert("listLen(thetoken, '.') EQ 3");

		// Decode the thetoken and get the data structure back. This is will throw an error if the thetoken is invalid
		result = jwtObj.decode(thetoken);
		assert("structKeyExists(result, 'name')");
		assert("structKeyExists(result, 'admin')");
		assert("result.name EQ 'John Doe'");
	}

	function Test_encode_and_decode_HS384(){
		thetoken = jwtObj.encode(testData.payload, "HS384");
		assert("listLen(thetoken, '.') EQ 3");
		result = jwtObj.decode(thetoken);
		assert("structKeyExists(result, 'name')");
		assert("structKeyExists(result, 'admin')");
		assert("result.name EQ 'John Doe'");
	}

	function Test_encode_and_decode_HS512(){
		thetoken = jwtObj.encode(testData.payload, "HS512");
		assert("listLen(thetoken, '.') EQ 3");
		result = jwtObj.decode(thetoken);
		assert("structKeyExists(result, 'name')");
		assert("structKeyExists(result, 'admin')");
		assert("result.name EQ 'John Doe'");
	}

	function Test_should_return_data_decoded_from_JWT_in_a_struct(){
		result = jwtObj.decode(testData.validToken);
		assert("isStruct(result)" );
		assert("result.sub EQ 1234567890" );
		assert("result.name EQ 'John Doe'" );
	}

	function Test_should_throw_an_error_for_token_with_an_invalid_format(){
		result=raised("jwtObj.decode(testData.invalidFormatToken)");
		assert("result EQ 'Invalid Token'");
	}

	function Test_should_throw_an_error_for_token_signed_with_the_wrong_key(){
		result=raised("jwtObj.decode(testData.invalidToken)");
		assert("result EQ 'Invalid Token'");
	}

	function Test_should_verify_token_nbf_Not_Before_claim(){
		data = jwtObj.decode(testData.validNotBefore);
		actual = DateAdd('s', data.nbf, DateConvert('utc2Local','January 1 1970 00:00') );
		assert(	"data.sub EQ 'xyz'" );
		assert( "actual LT now()");
	}

	function Test_should_fail_if_nbf_is_prior_to_current_date_and_time(){
		result=raised("jwtObj.decode(testData.expiredTokenWithClaims)");
		assert("result EQ 'Invalid Token'");
	}

	function Test_should_verify_token_is_not_expired(){
		data = jwtObj.decode(testData.tokenWithClaims);
		assert("data.name EQ 'John Doe'");
	}

	function Test_should_fail_for_an_expired_token(){
		result=raised("jwtObj.decode(testData.expiredTokenWithClaims)");
		assert("result EQ 'Invalid Token'");
	}

	function Test_should_not_fail_for_an_expired_token_when_ignoreExpiration_is_true(){
		jwtObj2=jwt(key=secretkey,ignoreExpiration=true);
		data = jwtObj2.decode(testData.expiredTokenWithClaims);
		assert("data.name EQ 'John Doe'");
	}

	function Test_should_verify_the_issuer_if_provided(){
		jwtObj3=jwt(key=secretkey,issuer="http://myapi");
		data = jwtObj3.decode(testData.tokenWithClaims);
		assert("data.iss EQ 'http://myapi'");
	}

	function Test_should_throw_an_error_if_issuer_does_not_match(){
		jwtObj4=jwt(key=secretkey,issuer="http://test.issuer.com");
		result = raised("jwtObj4.decode(testData.tokenWithClaims)");
		assert("result EQ 'Invalid Token'");
	}

	function Test_should_verify_the_audience_if_provided(){
		jwtObj5=jwt(key=secretkey,audience="clientid");
		data = jwtObj5.decode(testData.tokenWithClaims);
		assert("data.aud EQ 'clientid'");
	}

	function Test_should_throw_an_error_if_audience_does_not_match(){
		jwtObj6=jwt(key=secretkey,audience="xyz");
		result = raised("jwtObj6.decode(testData.tokenWithClaims)");
		assert("result EQ 'Invalid Token'");
	}

 }
