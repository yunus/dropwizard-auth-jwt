package com.github.toastshaman.dropwizard.auth.jwt.example;

import io.dropwizard.Configuration;
import org.hibernate.validator.constraints.NotEmpty;

import java.io.UnsupportedEncodingException;

public class MyConfiguration extends Configuration {

    @NotEmpty
    private String jwtTokenCertsfile = "listofcerts.jks";

	public String getJwtTokenCertsfile() {
		return jwtTokenCertsfile;
	}

	public void setJwtTokenCertsfile(String jwtTokenCertsfile) {
		this.jwtTokenCertsfile = jwtTokenCertsfile;
	}

}
