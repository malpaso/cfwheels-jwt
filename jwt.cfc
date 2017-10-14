/**
 * This is a cfwheels plugin of https://github.com/jsteinshouer/cf-jwt-simple
 * All credit to Jason Steinshouer
 **/
component name="jwt" hint="Plugin for encoding and decoding JSON Web Tokens." output="false" {

    function init(
        required string key,
        boolean ignoreExpiration=false,
        string issuer="",
        string audience=""
    ){
        this.version="1.4.5,2.0";

        variables.key = arguments.key;
        variables.ignoreExpiration = arguments.ignoreExpiration;
        variables.issuer = arguments.issuer;
        variables.audience = arguments.audience;

        variables.algorithmMap = {
            "HS256" = "HmacSHA256",
            "HS384" = "HmacSHA384",
            "HS512" = "HmacSHA512"
        };

        return this;
    }

    function decode( required string token ){
        // Token should contain 3 segments
		if ( listLen(arguments.token,".") neq 3 ) {
			throw type="Invalid Token" message="Token should contain 3 segments";
        }

		// Get
		var header = deserializeJSON(base64UrlDecode(listGetAt(arguments.token,1,".")));
		var payload = deserializeJSON(base64UrlDecode(listGetAt(arguments.token,2,".")));
        var signature = listGetAt(arguments.token,3,".");
        
        // Make sure the algorithm listed in the header is supported
		if ( listFindNoCase(structKeyList(algorithmMap),header.alg) eq false ){
			throw type="Invalid Token" message="Algorithm not supported";
        }

        // Verify claims
		if ( StructKeyExists(payload,"exp") and not variables.ignoreExpiration ){
			if ( epochTimeToLocalDate(payload.exp) lt now() ){
				throw type="Invalid Token" message="Signature verification failed: Token expired";
            }
        }
		if ( StructKeyExists(payload,"nbf") and epochTimeToLocalDate(payload.nbf) gt now() ){
			throw type="Invalid Token" message="Signature verification failed: Token not yet active";
        }
		if ( StructKeyExists(payload,"iss") and variables.issuer neq "" and payload.iss neq variables.issuer ){
			throw type="Invalid Token" message="Signature verification failed: Issuer does not match";
        }
		if ( StructKeyExists(payload,"aud") and variables.audience neq "" and payload.aud neq variables.audience ){
			throw type="Invalid Token" message="Signature verification failed: Audience does not match";
        }

        // Verify signature
		var signInput = listGetAt(arguments.token,1,".") & "." & listGetAt(arguments.token,2,".");
		if ( signature neq sign(signInput,algorithmMap[header.alg]) ){
			throw type="Invalid Token" message="Signature verification failed: Invalid key";
        }

        return payload;
    }

    function encode(required string payload, string algorithm="HS256"){

		// Default hash algorithm
		var hashAlgorithm = "HS256";
		var segments = "";

		// Make sure only supported algorithms are used
		if ( listFindNoCase(structKeyList(algorithmMap),arguments.algorithm) ){
			hashAlgorithm = arguments.algorithm;
        }

		// Add Header - typ and alg fields
		segments = listAppend(segments, base64UrlEscape(toBase64(serializeJSON({ "typ" =  "JWT", "alg" = hashAlgorithm }))),".");
		// Add payload
		segments = listAppend(segments, base64UrlEscape(toBase64(serializeJSON(arguments.payload))),".");
		segments = listAppend(segments, sign(segments,algorithmMap[hashAlgorithm]),".");

		return segments;
    }

    function verify( required string token ){
        var isValid = true;
        try{
            decode(arguments.token);
        }catch(any e){
            isValid = false;
        }
        return isValid;
    }

    private function sign( required string msg, string algorithm="HmacSHA256" ){
        var key = createObject("java", "javax.crypto.spec.SecretKeySpec").init(variables.key.getBytes(), arguments.algorithm);
		var mac = createObject("java", "javax.crypto.Mac").getInstance(arguments.algorithm);
		mac.init(key);

		return base64UrlEscape(toBase64(mac.doFinal(msg.getBytes())));
    }

    private function base64UrlEscape( required string str ){
        return reReplace(reReplace(reReplace(str, "\+", "-", "all"), "\/", "_", "all"),"=", "", "all");
    }

    private function base64UrlUnescape( required string str ){
        // Unescape url characters
		var base64String = reReplace(reReplace(arguments.str, "\-", "+", "all"), "\_", "/", "all");
		var padding = repeatstring("=",4 - len(base64String) mod 4);

		return base64String & padding;
    }

    private function base64UrlDecode( required string str ){
        return toString(toBinary(base64UrlUnescape(arguments.str)));
    }

    private function epochTimeToLocalDate( required numeric epoch ){
        return createObject("java","java.util.Date").init(arguments.epoch*1000);
    }
}