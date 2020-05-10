package com.aws.lambda.authorization;

import java.util.HashMap;
import java.util.Map;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

/**
 * Custom Auth
 *
 */
public class CustomAuthorizerHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {

	@Override
	public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
		String token = (String) event.get("authorizationToken");
		String resource = (String) event.get("methodArn");
		String principalId = "123";
		// Credit : https://github.com/bbilger/jrestless-examples/tree/master/aws/gateway/aws-gateway-security-custom-authorizer
		/*
		 * switch (token) { case "allow": return generatePolicy(principalId, "Allow",
		 * resource); case "deny": return generatePolicy(principalId, "Deny", resource);
		 * case "unauthorized": throw new RuntimeException("Unauthorized"); default:
		 * throw new RuntimeException("fail"); }
		 */
		// Credit : https://github.com/auth0/java-jwt
		/*
		 * String token =
		 * "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
		 * RSAPublicKey publicKey = //Get the key instance RSAPrivateKey privateKey =
		 * //Get the key instance try { Algorithm algorithm =
		 * Algorithm.RSA256(publicKey, privateKey); JWTVerifier verifier =
		 * JWT.require(algorithm) .withIssuer("auth0") .build(); //Reusable verifier
		 * instance DecodedJWT jwt = verifier.verify(token); } catch
		 * (JWTVerificationException exception){ //Invalid signature/claims }
		 */
		//String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
		try {
		    Algorithm algorithm = Algorithm.HMAC256("secret");
		    JWTVerifier verifier = JWT.require(algorithm)
		        .withIssuer("auth0")
		        .build(); //Reusable verifier instance
		    verifier.verify(token);
		} catch (JWTVerificationException exception){
			throw new RuntimeException("Unauthorized");
		}
		return generatePolicy(principalId, "Allow", resource);
	}

	private Map<String, Object> generatePolicy(String principalId, String effect, String resource) {
		Map<String, Object> authResponse = new HashMap<>();
		authResponse.put("principalId", principalId);
		Map<String, Object> policyDocument = new HashMap<>();
		policyDocument.put("Version", "2012-10-17"); // default version
		Map<String, String> statementOne = new HashMap<>();
		statementOne.put("Action", "execute-api:Invoke"); // default action
		statementOne.put("Effect", effect);
		statementOne.put("Resource", resource);
		policyDocument.put("Statement", new Object[] {statementOne});
		authResponse.put("policyDocument", policyDocument);
		if ("Allow".equals(effect)) {
			Map<String, Object> context = new HashMap<>();
			context.put("key", "value");
			context.put("numKey", Long.valueOf(1L));
			context.put("boolKey", Boolean.TRUE);
			authResponse.put("context", context);
		}
		return authResponse;
	}
}
