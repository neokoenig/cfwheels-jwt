component hint="jwt" output="false" mixin="global"
{
	public function init() {
		this.version 			= "2.0";
		return this;
	}

	/**
	*
	* Main entry point for jwt. `encode()`, `decode()`, `verify()` and `sign()` are available.
	*
	* [section: Plugins]
	* [category: JWT]
	*
	* @key Your Secret Key
	* @ignoreExpiration ignore `exp` claim during verification
	* @issuer add `iss` registered claims during verification
	* @audience add `aud` registered claims during verification
	*/
   	public any function jwt(
   		required key,
   		boolean ignoreExpiration="false",
   		string issuer="",
   		string audience=""
   	){
		var key 				= arguments.key;
		var ignoreExpiration 	= arguments.ignoreExpiration;
		var issuer 				= arguments.issuer;
		var audience 			= arguments.audience;
		//  Supported algorithms
		var algorithmMap = {
			"HS256" = "HmacSHA256",
			"HS384" = "HmacSHA384",
			"HS512" = "HmacSHA512"
		};
		/*
		decode(string) as struct
		Description:  Decode a JSON Web Token
		*/
		local.decode= function(required token){
			//  Token should contain 3 segments
			if ( listLen(arguments.token,".") != 3 ) {
				throw( message="Token should contain 3 segments", type="Invalid Token" );
			}
			//  Get
			var header = deserializeJSON($base64UrlDecode(listGetAt(arguments.token,1,".")));
			var payload = deserializeJSON($base64UrlDecode(listGetAt(arguments.token,2,".")));
			var signature = listGetAt(arguments.token,3,".");
			//  Make sure the algorithm listed in the header is supported
			if ( listFindNoCase(structKeyList(algorithmMap),header.alg) == false ) {
				throw( message="Algorithm not supported", type="Invalid Token" );
			}
			//  Verify claims
			if ( StructKeyExists(payload,"exp") && !ignoreExpiration ) {
				if ( $epochTimeToLocalDate(payload.exp) < now() ) {
					throw( message="Signature verification failed: Token expired", type="Invalid Token" );
				}
			}
			if ( StructKeyExists(payload,"nbf") && $epochTimeToLocalDate(payload.nbf) > now() ) {
				throw( message="Signature verification failed: Token not yet active", type="Invalid Token" );
			}
			if ( StructKeyExists(payload,"iss") && issuer != "" && payload.iss != issuer ) {
				throw( message="Signature verification failed: Issuer does not match", type="Invalid Token" );
			}
			if ( StructKeyExists(payload,"aud") && audience != "" && payload.aud != audience ) {
				throw( message="Signature verification failed: Audience does not match", type="Invalid Token" );
			}
			//  Verify signature
			var signInput = listGetAt(arguments.token,1,".") & "." & listGetAt(arguments.token,2,".");
			if ( signature != sign(signInput,algorithmMap[header.alg]) ) {
				throw( message="Signature verification failed: Invalid key", type="Invalid Token" );
			}
			return payload;
		}


		/*
		encode(struct,[string]) as String
		Description:  encode a data structure as a JSON Web Token
		*/
		local.encode = function(required payload, algorithm="HS256"){
			//  Default hash algorithm
			var hashAlgorithm = arguments.algorithm;
			var segments = "";
			//  Make sure only supported algorithms are used
			if ( listFindNoCase(structKeyList(algorithmMap),arguments.algorithm) ) {
				hashAlgorithm = arguments.algorithm;
			}
			//  Add Header - typ and alg fields
			segments = listAppend(segments, $base64UrlEscape(toBase64(serializeJSON({ "typ" =  "JWT", "alg" = hashAlgorithm }))),".");
			//  Add payload
			segments = listAppend(segments, $base64UrlEscape(toBase64(serializeJSON(arguments.payload))),".");
			segments = listAppend(segments, sign(segments,algorithmMap[hashAlgorithm]),".");
			return segments;
		}
		/*
		verify(token) as Boolean
		Description:  Verify the token signature
		*/
		local.verify=function(required token){
			var isValid = true;
			try {
				decode(token);
			} catch (any cfcatch) {
				isValid = false;
			}
			return isValid;
		}

		/*
		sign(string,[string]) as String
		Description: Create an MHAC of provided string using the secret key and algorithm
		*/
		local.sign=function(required string msg, algorithm="HmacSHA256"){
			var key = createObject("java", "javax.crypto.spec.SecretKeySpec").init(key.getBytes(), arguments.algorithm);
			var mac = createObject("java", "javax.crypto.Mac").getInstance(arguments.algorithm);
			mac.init(key);
			return $base64UrlEscape(toBase64(mac.doFinal(msg.getBytes())));
		}



		return local;
   	}


	/*  	$base64UrlEscape(String) as String
			Description:  Escapes unsafe url characters from a base64 string
	*/

	function $base64UrlEscape(required str) output=false {
		return reReplace(reReplace(reReplace(str, "\+", "-", "all"), "\/", "_", "all"),"=", "", "all");
	}
	/*  	$base64UrlUnescape(String) as String
			Description: restore base64 characters from an url escaped string
	*/

	function $base64UrlUnescape(required str) output=false {
		//  Unescape url characters
		var base64String = reReplace(reReplace(arguments.str, "\-", "+", "all"), "\_", "/", "all");
		var padding = repeatstring("=",4 - len(base64String) mod 4);
		return base64String & padding;
	}
	/*  	$base64UrlDecode(String) as String
			Description:  Decode a url encoded base64 string
	*/

	function $base64UrlDecode(required str) output=false {
		return toString(toBinary($base64UrlUnescape(arguments.str)));
	}
	/*  	$epochTimeToLocalDate(numeric) as Datetime
			Description:  Converts Epoch datetime to local date

			I changed the date conversion to use Java instead of dateAdd()
			because currently (12/12/2016), ACF dateAdd uses an integer so there is a limit
			of 2147483647 (Tue, 19 Jan 2038 03:14:07 GMT) which i doubt anyone
			will still use this in 2038 but I changed it anyway.
	*/

	function $epochTimeToLocalDate(required epoch) output=false {
		return createObject("java", "java.util.Date").init(epoch*1000);
	}
}
