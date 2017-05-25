<h1>CFWheels JWT</h1>

<p>CFWheels Plugin ported from existing CFML Component for encoding and decoding <a href="http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html">JSON Web Tokens (JWT)</a>.</p>
<p>Which in turn is a port of the node.js project <a href="https://github.com/hokaccha/node-jwt-simple">node-jwt-simple</a> to cfml. It currently supports HS256, HS384, and HS512 signing algorithms.</p>
<h2>Usage</h2>
<pre><code>&lt;cfscript&gt;
	// Initialize the component with the secret signing key
	jwtObj = jwt(secretkey);

	// Encode the data structure as a json web token
	// NB, using "token" as a variable name seems to cause issues
	thetoken = jwtObj.encode(payload);

	// Decode the thetoken and get the data structure back. This is will throw an error if the thetoken is invalid
	result = jwtObj.decode(thetoken);
&lt;/cfscript&gt;
</code></pre>
<h2>Support for registered claims</h2>
<p>Supports the <code>nbf</code> and <code>exp</code> registered claims that can be part of the payload. Verification of the token will fail if the token is not yet active or if the token is expired according to the <code>nbf</code> and <code>exp</code> claims. They should be numeric dates in Unix epoch time according to the JWT spec.</p>
<p>To ignore the <code>exp</code> claim during verification, pass <code>ignoreExpiration=true</code> when instantiating the JWT instance. For example:</p>
<pre><code>jwtObj = jwt(key=secretkey, ignoreExpiration=true);
</code></pre>
<p>Also supports the <code>aud</code> and <code>iss</code> registered claims during verification. If you don't pass <code>audience</code> or <code>issuer</code> during instantiation, the claims will be ignored during verification. If you do pass them, they'll be included during the verification process. Here's an example:</p>
<pre><code>jwtObj = jwt(key=secretkey, audience="myaudiencevalue", issuer="myissuervalue");
</code></pre>
