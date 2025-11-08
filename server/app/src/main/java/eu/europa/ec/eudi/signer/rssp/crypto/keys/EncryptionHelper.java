package eu.europa.ec.eudi.signer.rssp.crypto.keys;

import eu.europa.ec.eudi.signer.rssp.common.config.AuthProperties;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EncryptionHelper {
	private final Key encryptionKey;

	public EncryptionHelper(AuthProperties authProperties) throws Exception {
		char[] passphrase = authProperties.getDbEncryptionPassphrase().toCharArray();
		byte[] saltBytes = Base64.getDecoder().decode(authProperties.getDbEncryptionSalt());

		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(passphrase, saltBytes, 65536, 256);
		this.encryptionKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
	}

	public byte[] genInitializationVector(int iv_length){
		byte[] iv = new byte[iv_length];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(iv);
		return iv;
	}

	public byte[] encrypt(String transformation, byte[] iv, byte[] dataToEncrypt) throws Exception {
		AlgorithmParameterSpec algSpec = getAlgorithmSpec(transformation, iv);

		Cipher cipher = Cipher.getInstance(transformation);
		cipher.init(Cipher.ENCRYPT_MODE, this.encryptionKey, algSpec);
		return cipher.doFinal(dataToEncrypt);
	}

	public byte[] encrypt(String transformation, Key encryptionKey, byte[] iv, byte[] dataToEncrypt) throws Exception {
		AlgorithmParameterSpec algSpec = getAlgorithmSpec(transformation, iv);

		Cipher cipher = Cipher.getInstance(transformation);
		cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, algSpec);
		return cipher.doFinal(dataToEncrypt);
	}

	public byte[] decrypt(String transformation, byte[] iv, byte[] dataToDecrypt) throws Exception{
		AlgorithmParameterSpec algSpec = getAlgorithmSpec(transformation, iv);

		Cipher cipher = Cipher.getInstance(transformation);
		cipher.init(Cipher.DECRYPT_MODE, this.encryptionKey, algSpec);
		return cipher.doFinal(dataToDecrypt);
	}

	public byte[] decrypt(String transformation,  Key encryptionKey, byte[] iv, byte[] dataToDecrypt) throws Exception{
		AlgorithmParameterSpec algSpec = getAlgorithmSpec(transformation, iv);

		Cipher cipher = Cipher.getInstance(transformation);
		cipher.init(Cipher.DECRYPT_MODE, encryptionKey, algSpec);
		return cipher.doFinal(dataToDecrypt);
	}

	private AlgorithmParameterSpec getAlgorithmSpec(String transformation, byte[] iv){
		if (transformation.equals("AES/GCM/NoPadding"))
			return new GCMParameterSpec(128, iv);
		else if (transformation.equals("AES/CBC/PKCS5Padding"))
			return new IvParameterSpec(iv);
		else return null;
	}

}
