package com.co.cipherpoc.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.co.cipherpoc.service.CipherService;

@RestController
@RequestMapping("/cipher")
public class CipherController {

	@Autowired
	private CipherService cipherService;

	@GetMapping("/hello-world/{name}")
	public String hello(@PathVariable String name) throws Exception {
		String encryptedValue = cipherService.encrypt(name);
		String decryptedValue = cipherService.decrypt(encryptedValue);
		Assert.isTrue(decryptedValue.equals(name), "decryptedValue must be equal to name");

		return encryptedValue;
	}

}
