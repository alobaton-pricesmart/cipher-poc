package com.co.cipherpoc.service;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Service;

@Service
public class CipherService {

	private static final Log LOGGER = LogFactory.getLog(CipherService.class);

	// NOTE: This properties must be in a properties file.
	private static final int POOL_SIZE = 10;
	private static final String SECRET_KEY = "mySecret";
	private static final String SALT = "salt";

	private static final byte[] INITIALIZATION_VECTOR = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	private static final ConcurrentLinkedDeque<Cipher> ENCRYPT_POOL = new ConcurrentLinkedDeque<>();
	private static final ConcurrentLinkedDeque<Cipher> DECRYPT_POOL = new ConcurrentLinkedDeque<>();

	private Runnable checkPoolRunnable = new Runnable() {
		@Override
		public void run() {
			if (ENCRYPT_POOL.size() != POOL_SIZE) {
				try {
					fillEncryptPool();
				} catch (GeneralSecurityException e) {
					LOGGER.error(e);
				}
			}

			if (DECRYPT_POOL.size() != POOL_SIZE) {
				try {
					fillDecryptPool();
				} catch (GeneralSecurityException e) {
					LOGGER.error(e);
				}
			}
		}
	};

	@PostConstruct
	public void init() throws GeneralSecurityException {
		// Ciphers are expensive items to create by the JVM, because of that we must
		// create an object pool.
		// NOTE: You must use Apache Commons Pool instead of a manual pool.
		this.fillEncryptPool();
		this.fillDecryptPool();

		// Throw async a check pool method.
		// NOTE: If you use Apache Commons Pool you must not implement this.
		this.checkPool();
	}

	private void fillEncryptPool() throws GeneralSecurityException {
		// Ciphers are expensive items to create by the JVM, because of that we must
		// create an object pool.
		// NOTE: You must use Apache Commons Pool instead of a manual pool.
		// Initialization vector is necessary for any cipher in any feedback mode. (16)
		IvParameterSpec ivparameterSpec = new IvParameterSpec(INITIALIZATION_VECTOR);

		SecretKeyFactory secretFactory;
		try {
			secretFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Error on SecretKeyFactory.getInstance", e);
			throw e;
		}

		KeySpec keySpec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
		SecretKey secretKey;
		try {
			secretKey = secretFactory.generateSecret(keySpec);
		} catch (InvalidKeySpecException e) {
			LOGGER.error("Error on SecretKeyFactory.generateSecret", e);
			throw e;
		}

		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
		int itemsToCreate = POOL_SIZE - ENCRYPT_POOL.size();
		for (int i = 0; i < itemsToCreate; i++) {
			// Add to ENCRYPT_POOL
			Cipher encrypter;
			try {
				encrypter = Cipher.getInstance("AES/CBC/PKCS5Padding");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				LOGGER.error("Error on Cipher.getInstance", e);
				throw e;
			}
			try {
				encrypter.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivparameterSpec);
			} catch (InvalidKeyException e) {
				LOGGER.error("Error on cipher.init", e);
				throw e;
			}
			ENCRYPT_POOL.add(encrypter);
		}
	}

	private void fillDecryptPool() throws GeneralSecurityException {
		// Ciphers are expensive items to create by the JVM, because of that we must
		// create an object pool.
		// NOTE: You must use Apache Commons Pool instead of a manual pool.
		// Initialization vector is necessary for any cipher in any feedback mode. (16)
		IvParameterSpec ivparameterSpec = new IvParameterSpec(INITIALIZATION_VECTOR);

		SecretKeyFactory secretFactory;
		try {
			secretFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Error on SecretKeyFactory.getInstance", e);
			throw e;
		}

		KeySpec keySpec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
		SecretKey secretKey;
		try {
			secretKey = secretFactory.generateSecret(keySpec);
		} catch (InvalidKeySpecException e) {
			LOGGER.error("Error on SecretKeyFactory.generateSecret", e);
			throw e;
		}

		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
		int itemsToCreate = POOL_SIZE - DECRYPT_POOL.size();
		for (int i = 0; i < itemsToCreate; i++) {
			// Add to DECRYPT_POOL
			Cipher decrypter;
			try {
				decrypter = Cipher.getInstance("AES/CBC/PKCS5Padding");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				LOGGER.error("Error on Cipher.getInstance", e);
				throw e;
			}
			try {
				decrypter.init(Cipher.DECRYPT_MODE, secretKeySpec, ivparameterSpec);
			} catch (InvalidKeyException e) {
				LOGGER.error("Error on cipher.init", e);
				throw e;
			}
			DECRYPT_POOL.add(decrypter);
		}
	}

	private void checkPool() {
		ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
		executor.scheduleAtFixedRate(checkPoolRunnable, 0, 60, TimeUnit.SECONDS);
	}

	public String encrypt(String value) throws Exception {
		Cipher encrypter = ENCRYPT_POOL.poll();
		if (encrypter == null) {
			throw new Exception("encrypter is null!");
		}

		try {
			return Base64.getEncoder().encodeToString(encrypter.doFinal(value.getBytes("UTF-8")));
		} catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
			LOGGER.error("Error on encrypt", e);
			throw e;
		}
	}

	public String decrypt(String value) throws Exception {
		Cipher decrypter = DECRYPT_POOL.poll();
		if (decrypter == null) {
			throw new Exception("decrypter is null!");
		}

		try {
			return new String(decrypter.doFinal(Base64.getDecoder().decode(value)));
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			LOGGER.error("Error on encrypt", e);
			throw e;
		}
	}
}
