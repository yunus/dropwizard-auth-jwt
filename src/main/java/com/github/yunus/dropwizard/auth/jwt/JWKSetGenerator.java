package com.github.yunus.dropwizard.auth.jwt;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Enumeration;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

public class JWKSetGenerator {

	public static JWKSet fromX509Jks(String jksfile, char [] password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException   {

		FileInputStream is = new FileInputStream(jksfile);
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is,password);
		ArrayList<JWK> certificates = new ArrayList<>();
		for(Enumeration<String>  e = keystore.aliases(); e.hasMoreElements();){
			X509Certificate cert = (X509Certificate)keystore.getCertificate(e.nextElement());			
			certificates.add( new RSAKey.Builder((RSAPublicKey)cert.getPublicKey()).build());
		}
		return new JWKSet(certificates);




	}

}
