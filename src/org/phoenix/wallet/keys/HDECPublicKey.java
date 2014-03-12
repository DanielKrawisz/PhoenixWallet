package org.phoenix.wallet.keys;

import java.security.SignatureException;

import org.phoenix.random.Random;


import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.HDKeyDerivation;

public class HDECPublicKey implements HDPublicKey{
	DeterministicKey key;
	
	//Generate randomly 
	public HDECPublicKey() {
		key = HDKeyDerivation.createMasterPrivateKey(Random.get_bytes(16));
	}
	
	public HDECPublicKey(DeterministicKey k) {
		key = k.getPubOnly();
	}
	
	public HDECPublicKey(HDPublicKey k) {
		key = KeyTransformer.make_DeterministicKey(k);
	}
	
	public PublicKey get_PublicKey() {
		return new ECPublicKey(key.toECKey());
	}
	
	public HDPublicKey public_child(int n) {
		return new HDECPublicKey(KeyTransformer.clone_without_memory(HDKeyDerivation.deriveChildKey(key, n)));
	}

	@Override
	public boolean verify_signature(String doc, String sig) {
		try {
			key.toECKey().verifyMessage(doc, sig);
		} catch (SignatureException e) {
			return false;
		}
		return true;
	}

	@Override
	public HDPublicKey export_HDPublicKey() {
		return new HDECPublicKey(KeyTransformer.clone_without_memory(key));
	}

	@Override
	public ECKey to_ECKey() {
		return key.toECKey();
	}
}
