package eu.europa.ec.eudi.signer.rssp.crypto.keys;

import eu.europa.ec.eudi.signer.rssp.common.config.KeysProperties;
import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;
import eu.europa.ec.eudi.signer.rssp.common.error.SignerError;
import eu.europa.ec.eudi.signer.rssp.entities.SecretKey;
import eu.europa.ec.eudi.signer.rssp.hsm.HSMService;
import eu.europa.ec.eudi.signer.rssp.repository.ConfigRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

public class HsmKeysService implements IKeysService{
	private static final Logger logger = LoggerFactory.getLogger(HsmKeysService.class);
	private final HSMService hsmService;
	private final KeysProperties keysConfig;
	private static final int IVLENGTH = 12;

	public HsmKeysService(HSMService hsmService, KeysProperties keysProperties, EncryptionHelper encryptionHelper, ConfigRepository configRep) throws Exception {
		this.keysConfig = keysProperties;
		this.hsmService = hsmService;

		List<SecretKey> secretKeys = configRep.findAll();
		if (secretKeys.isEmpty()) {
			// generates a secret key to wrap the private keys from the HSM
			byte[] secretKeyBytes = this.hsmService.initSecretKey();
			byte[] iv = encryptionHelper.genInitializationVector(IVLENGTH);

			// encrypts the secret key before saving it in the db
			byte[] encryptedSecretKeyBytes = encryptionHelper.encrypt("AES/GCM/NoPadding", iv, secretKeyBytes);

			ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedSecretKeyBytes.length);
			byteBuffer.put(iv);
			byteBuffer.put(encryptedSecretKeyBytes);

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
			byte[] encryptedSecretKey = new byte[byteBuffer.remaining()];
			byteBuffer.get(encryptedSecretKey);

			// decrypts the secret key
			byte[] secretKeyBytes = encryptionHelper.decrypt("AES/GCM/NoPadding", iv, encryptedSecretKey);

			// loads the decrypted key to the HSM
			this.hsmService.setSecretKey(secretKeyBytes);
		}
	}

	/**
	 * Function that allows to create a key pair
	 * Exception: if the algorithm define in the application.yml for key creation is
	 * not supported
	 * Exception: if the hsm could not generate a key pair
	 *
	 * @return the private key wrapped, the modulus of the public key and the public
	 *         exponent
	 */
	@Override
	public KeyPairDTO generateKeyPair() throws ApiException {
		if (!this.keysConfig.getKeyAlgorithm().equals("RSA")) {
			logger.error("The algorithm {} for key pair creation is not supported by the current implementation.", this.keysConfig.getKeyAlgorithm());
			throw new ApiException(SignerError.AlgorithmNotSupported, "The algorithm " + this.keysConfig.getKeyAlgorithm()
				  + " for key pair creation is not supported by the current implementation.");
		}

		try {
			byte[][] hsmKeyPair = this.hsmService.generateRSAKeyPair(this.keysConfig.getKeySize());
			byte[] privKeyValues = hsmKeyPair[0];

			byte[] modulus = hsmKeyPair[1];
			BigInteger modulusBI = new BigInteger(1, modulus);
			byte[] public_exponent = hsmKeyPair[2];
			BigInteger publicExponentBI = new BigInteger(1, public_exponent);
			KeyFactory keyFactory = KeyFactory.getInstance(this.keysConfig.getKeyAlgorithm());
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulusBI, publicExponentBI);
			PublicKey pk = keyFactory.generatePublic(keySpec);

			return new KeyPairDTO(pk, privKeyValues);
		} catch (Exception e) { // Fail to generate the RSA Key Pair
			logger.error("{}: {}", SignerError.FailedCreatingKeyPair.getFormattedMessage(), e.getMessage());
			throw new ApiException(SignerError.FailedCreatingKeyPair, SignerError.FailedCreatingKeyPair.getDescription());
		}
	}

	@Override
	public byte[] sign (byte[] privKeyValues, byte[] data) throws Exception {
		return hsmService.signDTBSwithRSAPKCS11(privKeyValues, data);
	}
}
