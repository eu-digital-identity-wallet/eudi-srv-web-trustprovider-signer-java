package eu.europa.ec.eudi.signer.rssp.crypto.keys;

import java.security.PublicKey;

public record KeyPairDTO(PublicKey publicKey, byte[] encryptedPrivateKey) {
}
