# CFWheels JWT

## Description

[![Build Status](https://travis-ci.org/neokoenig/cfwheels-jwt.svg?branch=master)](https://travis-ci.org/neokoenig/cfwheels-jwt)

CFWheels Plugin ported from existing CFML Component by [Jason Steinshouer](https://github.com/jsteinshouer/cf-jwt-simple) for encoding and decoding [JSON Web Tokens (JWT)](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html), which in turn is a port of the node.js project [node-jwt-simple](https://github.com/hokaccha/node-jwt-simple) to cfml.

It currently supports HS256, HS384, and HS512 signing algorithms.

## Usage
	<cfscript>
		// Initialize the component with the secret signing key
		jwtObj = jwt(secretkey);

		// Encode the data structure as a json web token
		// NB, using "token" as a variable name seems to cause issues
		thetoken = jwtObj.encode(payload);

		// Decode the thetoken and get the data structure back. This is will throw an error if the thetoken is invalid
		result = jwtObj.decode(thetoken);
	</cfscript>

## Support for registered claims

Supports the `nbf` and `exp` registered claims that can be part of the payload. Verification of the token will fail if the token is not yet active or if the token is expired according to the `nbf` and `exp` claims. They should be numeric dates in Unix epoch time according to the JWT spec.

To ignore the `exp` claim during verification, pass `ignoreExpiration=true` when instantiating the JWT instance. For example:

	jwtObj = jwt(key=secretkey, ignoreExpiration=true);

Also supports the `aud` and `iss` registered claims during verification. If you don't pass `audience` or `issuer` during instantiation, the claims will be ignored during verification. If you do pass them, they'll be included during the verification process. Here's an example:

	jwtObj = jwt(key=secretkey, audience="myaudiencevalue", issuer="myissuervalue");
