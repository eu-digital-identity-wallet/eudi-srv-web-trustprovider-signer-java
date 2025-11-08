package eu.europa.ec.eudi.signer.rssp.crypto.keys;

import eu.europa.ec.eudi.signer.rssp.common.config.KeysProperties;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.repository.ConfigRepository;
import eu.europa.ec.eudi.signer.rssp.entities.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

public class LocalKeysService implements IKeysService{

	private static final Logger logger = LoggerFactory.getLogger(LocalKeysService.class);
	private final EncryptionHelper encryptionHelper;
	private final KeysProperties config;
	private static final int IVLENGTH = 12;
	private javax.crypto.SecretKey skEncryptionKey;
	private final byte[] skEncryptionIV;

	public LocalKeysService(KeysProperties keysProperties, EncryptionHelper encryptionHelper, ConfigRepository configRep) throws Exception {
		this.config = keysProperties;
		this.encryptionHelper = encryptionHelper;

		List<SecretKey> secretKeys = configRep.findAll();
		int ENCRYPTION_IV_LENGTH = 16;
		if (secretKeys.isEmpty()) {
			this.skEncryptionIV = encryptionHelper.genInitializationVector(ENCRYPTION_IV_LENGTH);

			// generates a secret key to wrap the private keys from the HSM
			byte[] secretKeyBytes = initSecretKey();
			byte[] iv = encryptionHelper.genInitializationVector(IVLENGTH);

			byte[] encryptedSecretKeyBytes = encryptionHelper.encrypt("AES/GCM/NoPadding", iv, secretKeyBytes);

			ByteBuffer byteBuffer = ByteBuffer.allocate(IVLENGTH + encryptedSecretKeyBytes.length + ENCRYPTION_IV_LENGTH);
			byteBuffer.put(iv);
			byteBuffer.put(encryptedSecretKeyBytes);
			byteBuffer.put(this.skEncryptionIV);

			// saves in the db
			SecretKey sk = new SecretKey(byteBuffer.array());
			configRep.save(sk);
		} else {
			// loads the encrypted key from the database
			SecretKey sk = secretKeys.get(0);
			byte[] encryptedSecretKeyBytes = sk.getSecretKey();

			ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedSecretKeyBytes);
			byte[] iv = new byte[IVLENGTH];
			byteBuffer.get(iv);
			byte[] encryptedSecretKey = new byte[byteBuffer.remaining() - ENCRYPTION_IV_LENGTH];
			byteBuffer.get(encryptedSecretKey);
			this.skEncryptionIV = new byte[ENCRYPTION_IV_LENGTH];
			byteBuffer.get(this.skEncryptionIV);

			// decrypts the secret key
			byte[] secretKeyBytes = encryptionHelper.decrypt("AES/GCM/NoPadding", iv, encryptedSecretKey);

			// loads the decrypted key to the HSM
			setSkEncryptionKey(secretKeyBytes);
		}
	}

	private byte[] initSecretKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		javax.crypto.SecretKey secretKey = keyGen.generateKey();
		this.skEncryptionKey = secretKey;
		logger.info("Generated secret key to encrypt private keys.");
		return secretKey.getEncoded();
	}

	private void setSkEncryptionKey(byte[] skEncryptionKey){
		this.skEncryptionKey = new SecretKeySpec(skEncryptionKey,  "AES");
		logger.info("Loaded secret key to encrypt private keys.");
	}

	@Override
	public KeyPairDTO generateKeyPair() throws ApiException {
		if (!this.config.getKeyAlgorithm().equals("RSA")) {
			logger.error("The algorithm {} for key pair creation is not supported by the current implementation.", this.config.getKeyAlgorithm());
			throw new ApiException(SignerError.AlgorithmNotSupported, "The algorithm " + this.config.getKeyAlgorithm()
				  + " for key pair creation is not supported by the current implementation.");
		}

		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(this.config.getKeyAlgorithm());
			generator.initialize(this.config.getKeySize());
			KeyPair pair = generator.generateKeyPair();
			byte[] encryptedPrivateKey = encryptionHelper.encrypt("AES/CBC/PKCS5Padding", this.skEncryptionKey, this.skEncryptionIV, pair.getPrivate().getEncoded());
			return new KeyPairDTO(pair.getPublic(), encryptedPrivateKey);
		} catch (Exception e) { // Fail to generate the RSA Key Pair
			logger.error("{}: {}", SignerError.FailedCreatingKeyPair.getFormattedMessage(), e.getMessage());
			throw new ApiException(SignerError.FailedCreatingKeyPair, SignerError.FailedCreatingKeyPair.getDescription());
		}
	}

	@Override
	public byte[] sign(byte[] encodedPrivateKey, byte[] data) throws Exception {
		byte[] privateKeyBytes = encryptionHelper.decrypt("AES/CBC/PKCS5Padding", this.skEncryptionKey, this.skEncryptionIV, encodedPrivateKey);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory kf = KeyFactory.getInstance(this.config.getKeyAlgorithm());
		PrivateKey privateKey = kf.generatePrivate(spec);

		Signature signer = Signature.getInstance(this.config.getSignatureAlgorithm());
		signer.initSign(privateKey);
		signer.update(data); // input data to be signed
		return  signer.sign();
	}
}
