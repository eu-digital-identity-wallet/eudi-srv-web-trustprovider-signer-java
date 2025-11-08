package eu.europa.ec.eudi.signer.rssp.crypto.keys;

import eu.europa.ec.eudi.signer.rssp.common.error.ApiException;

public interface IKeysService {
	KeyPairDTO generateKeyPair() throws ApiException;
	byte[] sign (byte[] privKeyValues, byte[] csrInfo) throws Exception;
}
