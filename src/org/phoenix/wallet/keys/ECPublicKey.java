package org.phoenix.wallet.keys;

import java.security.SignatureException;

import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.crypto.DeterministicKey;

//An elliptic curve public key.
public class ECPublicKey implements PublicKey{
	ECKey key;
	
	protected ECPublicKey() {}
	
	public ECPublicKey(ECKey k) {
		key = k;
	}
	
	public ECPublicKey(PublicKey k) {
		key = KeyTransformer.make_ECKey(k);
	}
	
	public ECPublicKey(DeterministicKey k) {
		key = k.getPubOnly().toECKey();
	}

	@Override
	public boolean verify_signature(String doc, String sig) {
		try {
			key.verifyMessage(doc, sig);
		} catch (SignatureException e) {
			return false;
		}
		return true;
	}
	
	public ECKey to_ECKey() {
		return key;
	}
}
