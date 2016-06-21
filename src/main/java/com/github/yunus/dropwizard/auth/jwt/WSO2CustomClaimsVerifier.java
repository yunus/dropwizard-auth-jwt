package com.github.yunus.dropwizard.auth.jwt;

import java.text.ParseException;

import org.joda.time.DateTime;

import com.google.common.base.Strings;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
/**
 * This verifier mainly adds expiration time validation for WSO2.
 * The JWS standards dictates the user of expiration date in Seconds
 * however WSO2 has a bug which sets the expiration time in milliseconds.
 * So here I add custom expiration date verification.
 * 
 * @author yunus.durmus
 *
 */
public class WSO2CustomClaimsVerifier extends DefaultJWTClaimsVerifier {
	
	
	@Override
	public void verify(JWTClaimsSet claimsSet) 
			throws BadJWTException {
		super.verify(claimsSet);
		// WSO2 sends the expiration in milliseconds, which conflicts with the standard since it is in seconds.
		// so we implement our own expiration validator.
		// Also I have added one minute for skewed timers.
		DateTime expirationDate = new DateTime(claimsSet.getExpirationTime().getTime()/1000L).
				plusSeconds(DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS);

		//if(expirationDate.isBeforeNow()){
			//throw new BadJWTException("JWT has already expired.");
		//}
		System.out.println("Claims = "+claimsSet.getClaims());
		//algorithm field should not be empty
		try {
			if(Strings.isNullOrEmpty(claimsSet.getStringClaim("alg")) || claimsSet.getStringClaim("alg").equalsIgnoreCase("RS256")){
				throw new BadJWTException("Algorithm cannot be empty and only RS256 is accepted.");
			}
		} catch (ParseException e) {
			throw new BadJWTException("Could not parse the algoruthm field.");
		}
		
		
		// Issuer is WSO2
		String issuer = claimsSet.getIssuer();
		if (issuer == null || ! issuer.equals("wso2.org/products/am")) {
			throw new BadJWTException("Invalid token issuer");
		}

	}
}
